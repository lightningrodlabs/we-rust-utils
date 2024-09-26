use holochain_types::app::{AppBundle, AppManifest};
use holochain_types::prelude::YamlProperties;
use holochain_types::web_app::WebAppBundle;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::utils::hash_bytes_sha256;

#[napi(object)]
pub struct HappAndUiHashes {
    pub happ_sha256: String,
    pub webhapp_sha256: Option<String>,
    pub ui_sha256: Option<String>,
}

#[napi(object)]
pub struct StoredHappPathAndHashes {
    pub happ_path: String,
    pub happ_sha256: String,
    pub webhapp_sha256: Option<String>,
    pub ui_sha256: Option<String>,
}

#[napi]
pub async fn happ_bytes_with_custom_properties(
    happ_path: String,
    properties: HashMap<String, Option<String>>,
) -> napi::Result<Vec<u8>> {
    // 1. read and decode happ bundle
    let happ_bytes = fs::read(happ_path)?;
    let app_bundle = AppBundle::decode(&happ_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Failed to decode happ file: {}", e)))?;

    let mut manifest = app_bundle.manifest().clone();

    match manifest {
        AppManifest::V1(ref mut m) => {
            for role_manifest in m.roles.iter_mut() {
                match properties.get(&role_manifest.name) {
                    Some(maybe_props) => match maybe_props {
                        Some(props) => {
                            let yaml_value = serde_yaml::from_str::<
                                lair_keystore_api::dependencies::serde_yaml::Value,
                            >(props)
                            .map_err(|e| {
                                napi::Error::from_reason(format!(
                                    "Failed to convert properties to yaml Value: {e}"
                                ))
                            })?;
                            println!("yaml_value: {:?}", yaml_value);
                            let yaml_properties = YamlProperties::from(yaml_value);
                            role_manifest.dna.modifiers.properties = Some(yaml_properties);
                        }
                        None => {
                            role_manifest.dna.modifiers.properties = None;
                        }
                    },
                    None => (),
                }
            }
        }
    }

    let modified_bundle = app_bundle
        .into_inner()
        .update_manifest(manifest)
        .map_err(|e| napi::Error::from_reason(format!("Failed to update manifest: {e}")))?;

    let modified_app_bundle = AppBundle::from(modified_bundle);

    let app_bundle_bytes = modified_app_bundle.encode().map_err(|e| {
        napi::Error::from_reason(format!(
            "Failed to encode modified AppBundle to bytes: {}",
            e
        ))
    })?;

    Ok(app_bundle_bytes)
}

/// Saves a happ or a webhapp file. If a uis_dir is specified and it is a webhapp,
/// then the UI will be stored in [uis_dir]/[sha 256 of UI]/assets. If no uis_dir
/// is specified, only the happ file will be stored.
#[napi]
pub async fn save_happ_or_webhapp(
    happ_or_web_happ_path: String,
    happs_dir: String,
    uis_dir: Option<String>,
) -> napi::Result<StoredHappPathAndHashes> {
    let happ_or_webhapp_bytes = fs::read(happ_or_web_happ_path)?;

    match WebAppBundle::decode(&happ_or_webhapp_bytes) {
        Ok(web_app_bundle) => {
            let web_happ_hash = hash_bytes_sha256(happ_or_webhapp_bytes);

            // extracting ui.zip bytes
            let web_ui_zip_bytes = web_app_bundle.web_ui_zip_bytes().await.map_err(|e| {
                napi::Error::from_reason(format!("Failed to extract ui zip bytes: {}", e))
            })?;

            let ui_hash = hash_bytes_sha256(web_ui_zip_bytes.clone().into_owned().into_inner());

            // extracting happ bundle
            let app_bundle = web_app_bundle.happ_bundle().await.map_err(|e| {
                napi::Error::from_reason(format!(
                    "Failed to get happ bundle from webapp bundle bytes: {}",
                    e
                ))
            })?;

            let app_bundle_bytes = app_bundle.encode().map_err(|e| {
                napi::Error::from_reason(format!("Failed to encode happ to bytes: {}", e))
            })?;

            let happ_hash = hash_bytes_sha256(app_bundle_bytes);

            let happ_path = PathBuf::from(happs_dir).join(format!("{}.happ", happ_hash));
            let happ_path_string = happ_path
                .as_os_str()
                .to_str()
                .ok_or("Failed to convert happ path to string")
                .map_err(|e| napi::Error::from_reason(e))?;

            // Store UI if uis_dir is specified
            match uis_dir {
                Some(dir) => {
                    let ui_target_dir = PathBuf::from(dir).join(ui_hash.clone()).join("assets");
                    if !path_exists(&ui_target_dir) {
                        fs::create_dir_all(&ui_target_dir)?;
                    }

                    let ui_zip_path = PathBuf::from(ui_target_dir.clone()).join("ui.zip");

                    // unzip and store UI
                    fs::write(
                        ui_zip_path.clone(),
                        web_ui_zip_bytes.into_owned().into_inner(),
                    )
                    .map_err(|e| {
                        napi::Error::from_reason(format!("Failed to write Web UI Zip file: {}", e))
                    })?;

                    let file = fs::File::open(ui_zip_path.clone()).map_err(|e| {
                        napi::Error::from_reason(format!("Failed to read Web UI Zip file: {}", e))
                    })?;

                    unzip_file(file, ui_target_dir.into()).map_err(|e| {
                        napi::Error::from_reason(format!("Failed to unzip ui.zip: {}", e))
                    })?;

                    fs::remove_file(ui_zip_path).map_err(|e| {
                        napi::Error::from_reason(format!(
                            "Failed to remove ui.zip after unzipping: {}",
                            e
                        ))
                    })?;
                }
                None => (),
            }

            app_bundle.write_to_file(&happ_path).await.map_err(|e| {
                napi::Error::from_reason(format!("Failed to write .happ file: {}", e))
            })?;

            Ok(StoredHappPathAndHashes {
                happ_path: happ_path_string.into(),
                happ_sha256: happ_hash,
                webhapp_sha256: Some(web_happ_hash),
                ui_sha256: Some(ui_hash),
            })
        }
        Err(_) => {
            let app_bundle = AppBundle::decode(&happ_or_webhapp_bytes).map_err(|e| {
                napi::Error::from_reason(format!("Failed to decode happ file: {}", e))
            })?;

            let app_bundle_bytes = app_bundle.encode().map_err(|e| {
                napi::Error::from_reason(format!("Failed to encode happ to bytes: {}", e))
            })?;

            let happ_hash = hash_bytes_sha256(app_bundle_bytes);

            let happ_path = PathBuf::from(happs_dir).join(format!("{}.happ", happ_hash));
            let happ_path_string = happ_path
                .as_os_str()
                .to_str()
                .ok_or("Failed to convert happ path to string")
                .map_err(|e| napi::Error::from_reason(e))?;

            app_bundle.write_to_file(&happ_path).await.map_err(|e| {
                napi::Error::from_reason(format!("Failed to write .happ file: {}", e))
            })?;
            Ok(StoredHappPathAndHashes {
                happ_path: happ_path_string.into(),
                happ_sha256: happ_hash,
                webhapp_sha256: None,
                ui_sha256: None,
            })
        }
    }
}

/// Checks that the happ or webhapp is of the correct format
/// WARNING: The decoding and encoding of the happ bytes seems to affect happ's sha256 hash.
#[napi]
pub async fn validate_happ_or_webhapp(
    happ_or_webhapp_bytes: Vec<u8>,
) -> napi::Result<HappAndUiHashes> {
    let (app_bundle, maybe_ui_and_webhapp_hash) = match WebAppBundle::decode(&happ_or_webhapp_bytes)
    {
        Ok(web_app_bundle) => {
            let mut hasher = Sha256::new();
            hasher.update(happ_or_webhapp_bytes);
            let web_happ_hash = hex::encode(hasher.finalize());
            // extracting ui.zip bytes
            let web_ui_zip_bytes = web_app_bundle.web_ui_zip_bytes().await.map_err(|e| {
                napi::Error::from_reason(format!("Failed to extract ui zip bytes: {}", e))
            })?;

            let mut hasher = Sha256::new();
            hasher.update(web_ui_zip_bytes.clone().into_owned().into_inner());
            let ui_hash = hex::encode(hasher.finalize());

            // extracting happ bundle
            let app_bundle = web_app_bundle.happ_bundle().await.map_err(|e| {
                napi::Error::from_reason(format!(
                    "Failed to get happ bundle from webapp bundle bytes: {}",
                    e
                ))
            })?;

            (app_bundle, Some((ui_hash, web_happ_hash)))
        }
        Err(_) => {
            let app_bundle = AppBundle::decode(&happ_or_webhapp_bytes).map_err(|e| {
                napi::Error::from_reason(format!("Failed to decode happ file: {}", e))
            })?;
            (app_bundle, None)
        }
    };

    let mut hasher = Sha256::new();
    let app_bundle_bytes = app_bundle
        .encode()
        .map_err(|e| napi::Error::from_reason(format!("Failed to encode happ to bytes: {}", e)))?;
    hasher.update(app_bundle_bytes);
    let happ_hash = hex::encode(hasher.finalize());

    match maybe_ui_and_webhapp_hash {
        Some((ui_hash, web_happ_hash)) => Ok(HappAndUiHashes {
            happ_sha256: happ_hash,
            webhapp_sha256: Some(web_happ_hash),
            ui_sha256: Some(ui_hash),
        }),
        None => Ok(HappAndUiHashes {
            happ_sha256: happ_hash,
            webhapp_sha256: None,
            ui_sha256: None,
        }),
    }
}

pub fn path_exists(path: &PathBuf) -> bool {
    std::path::Path::new(path).exists()
}

pub fn unzip_file(reader: fs::File, outpath: PathBuf) -> Result<(), String> {
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => return Err(format!("Failed to unpack zip archive: {}", e)),
    };

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = match file.enclosed_name() {
            Some(path) => outpath.join(path).to_owned(),
            None => continue,
        };

        if (&*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath).unwrap();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p).unwrap();
                }
            }
            let mut outfile = fs::File::create(&outpath).unwrap();
            std::io::copy(&mut file, &mut outfile).unwrap();
        }
    }

    Ok(())
}
