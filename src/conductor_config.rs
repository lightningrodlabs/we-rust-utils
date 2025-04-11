#![deny(clippy::all)]

use holochain_conductor_api::{
    conductor::{paths::DataRootPath, ConductorConfig, DpkiConfig, KeystoreConfig, NetworkConfig},
    AdminInterfaceConfig, InterfaceDriver,
};
use holochain_types::websocket::AllowedOrigins;
use napi::{Error, Result, Status};
use napi_derive::napi;
use std::{collections::HashSet, path::PathBuf};

fn create_error(msg: &str) -> Error {
    Error::new(Status::GenericFailure, String::from(msg))
}

fn webrtc_config_from_ice_urls(ice_server_urls: Vec<String>) -> serde_json::Value {
    let mut webrtc_config = serde_json::Map::new();
    let mut ice_servers = Vec::new();
    for url in ice_server_urls {
        let mut url_mapping = serde_json::Map::new();
        url_mapping.insert(
            String::from("urls"),
            serde_json::Value::Array(vec![serde_json::Value::String(url)]),
        );
        ice_servers.push(serde_json::Value::Object(url_mapping));
    }
    webrtc_config.insert(
        String::from("iceServers"),
        serde_json::Value::Array(ice_servers),
    );
    serde_json::Value::Object(webrtc_config)
}

#[napi]
pub fn overwrite_config(
    admin_port: u16,
    config_path: String,
    keystore_connection_url: String,
    bootstrap_server_url: String,
    signaling_server_url: String,
    allowed_origin: String,
    use_dpki: bool,
    ice_server_urls: Option<Vec<String>>,
    keystore_in_proc_environment_dir: Option<String>,
) -> Result<String> {
    let mut config = std::fs::read_to_string(&PathBuf::from(config_path))
        .map_err(|_| create_error("Failed to read file"))
        .and_then(|contents| {
            serde_yaml::from_str::<ConductorConfig>(&contents)
                .map_err(|_| create_error("Failed to parse conductor-config.yaml"))
        })?;

    config.network.bootstrap_url = url2::url2!("{}", bootstrap_server_url);
    config.network.signal_url = url2::url2!("{}", signaling_server_url);
    config.network.webrtc_config = if ice_server_urls.is_some() {
        Some(webrtc_config_from_ice_urls(ice_server_urls.unwrap()))
    } else {
        None
    };

    config.admin_interfaces = Some(vec![AdminInterfaceConfig {
        driver: InterfaceDriver::Websocket {
            port: admin_port,
            allowed_origins: AllowedOrigins::Origins(HashSet::from([allowed_origin])),
        },
    }]);

    config.dpki = match use_dpki {
        true => DpkiConfig::default(),
        false => DpkiConfig::disabled(),
    };

    // If a keystore environment directory for in-process lair is provided, ignore
    // the value passed with keystore_connection_url
    config.keystore = match keystore_in_proc_environment_dir {
        Some(path) => KeystoreConfig::LairServerInProc {
            lair_root: Some(PathBuf::from(path).into()),
        },
        None => KeystoreConfig::LairServer {
            connection_url: url2::url2!("{}", keystore_connection_url),
        },
    };

    serde_yaml::to_string(&config)
        .map_err(|_| create_error("Could not convert conductor config to string"))
}

#[napi]
pub fn default_conductor_config(
    admin_port: u16,
    conductor_environment_path: String,
    keystore_connection_url: String,
    bootstrap_server_url: String,
    signaling_server_url: String,
    allowed_origin: String,
    use_dpki: bool,
    ice_server_urls: Option<Vec<String>>,
    keystore_in_proc_environment_dir: Option<String>,
) -> Result<String> {
    let mut network_config = NetworkConfig::default();
    network_config.bootstrap_url = url2::url2!("{}", bootstrap_server_url);
    network_config.signal_url = url2::url2!("{}", signaling_server_url);

    let webrtc_config = match ice_server_urls {
        Some(urls) => Some(webrtc_config_from_ice_urls(urls)),
        None => None,
    };

    network_config.webrtc_config = webrtc_config;

    let mut allowed_origins_map = HashSet::new();
    allowed_origins_map.insert(allowed_origin);

    let dpki_config = match use_dpki {
        true => DpkiConfig::default(),
        false => DpkiConfig::disabled(),
    };

    // If a keystore environment directory for in-process lair is provided, ignore
    // the value passed with keystore_connection_url
    let keystore_config = match keystore_in_proc_environment_dir {
        Some(path) => KeystoreConfig::LairServerInProc {
            lair_root: Some(PathBuf::from(path).into()),
        },
        None => KeystoreConfig::LairServer {
            connection_url: url2::url2!("{}", keystore_connection_url),
        },
    };

    let config = ConductorConfig {
        data_root_path: Some(DataRootPath::from(PathBuf::from(
            conductor_environment_path,
        ))),
        dpki: dpki_config,
        device_seed_lair_tag: None,
        danger_generate_throwaway_device_seed: false,
        keystore: keystore_config,
        admin_interfaces: Some(vec![AdminInterfaceConfig {
            driver: InterfaceDriver::Websocket {
                port: admin_port,
                allowed_origins: AllowedOrigins::Origins(allowed_origins_map),
            },
        }]),
        network: network_config,
        db_sync_strategy: Default::default(),
        tracing_override: None,
        tuning_params: None,
        tracing_scope: None,
    };

    serde_yaml::to_string(&config)
        .map_err(|_| create_error("Failed to convert conductor config to yaml string."))
}
