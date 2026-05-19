//! Computes a "legacy" sha256 for happ bundles that were packed and hashed
//! by an older version of we-rust-utils than the one currently linked into
//! Moss.
//!
//! The hash a publisher records in a tool-list entry is the sha256 of the
//! gzipped-msgpack output of `AppBundle::unpack(.)` then `pack()`. Whenever
//! `holochain_types` changes its manifest schema, that round-trip produces
//! different bytes for the same input, so the published hash no longer
//! matches what current code computes.
//!
//! Historical Moss releases (notably `we-rust-utils@0.600.0-dev.0`, shipped
//! with Moss 0.15.6) were built against `holochain_types@0.6.0-dev.28`. In
//! that schema, `AppManifestV0` had only `name`, `description`, `roles`, and
//! `allow_deferred_memproofs` — no `bootstrap_url`, `signal_url`, or
//! `relay_url`. Unpacking strips any of those fields a bundle may contain;
//! repacking does not re-emit them. That is the byte stream the publisher
//! hashed.
//!
//! To reproduce that hash without depending on two versions of
//! `holochain_types`, we decode the bundle through a generic representation
//! (`rmpv::Value` for the manifest), strip the known-added fields, and
//! re-encode. For bundles that never had those fields the round-trip is a
//! no-op and the hash matches the raw inner bytes (which is also what the
//! publisher hashed for those tools).

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use holochain_types::web_app::WebAppBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};

#[derive(Serialize, Deserialize)]
struct RawBundle {
    manifest: rmpv::Value,
    resources: BTreeMap<String, serde_bytes::ByteBuf>,
}

/// Fields present in some published bundles that the 0.6.0-dev.28 schema
/// (used by Moss 0.15.6's bundled we-rust-utils) does not know about and
/// silently drops on unpack.
const STRIPPED_MANIFEST_FIELDS: &[&str] = &["signal_url", "bootstrap_url", "relay_url"];

fn strip_legacy_unknown_fields(manifest: &mut rmpv::Value) {
    if let rmpv::Value::Map(entries) = manifest {
        entries.retain(|(k, _)| match k.as_str() {
            Some(s) => !STRIPPED_MANIFEST_FIELDS.contains(&s),
            None => true,
        });
    }
}

fn legacy_hash_of_happ_bytes(happ_bytes: &[u8]) -> napi::Result<String> {
    let mut gz = GzDecoder::new(happ_bytes);
    let mut msgpack_bytes = Vec::new();
    gz.read_to_end(&mut msgpack_bytes)
        .map_err(|e| napi::Error::from_reason(format!("Failed to gunzip happ bytes: {e}")))?;

    let mut bundle: RawBundle = rmp_serde::from_slice(&msgpack_bytes).map_err(|e| {
        napi::Error::from_reason(format!("Failed to decode happ msgpack: {e}"))
    })?;

    strip_legacy_unknown_fields(&mut bundle.manifest);

    let repacked = rmp_serde::to_vec_named(&bundle).map_err(|e| {
        napi::Error::from_reason(format!("Failed to re-encode happ msgpack: {e}"))
    })?;

    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&repacked)
        .map_err(|e| napi::Error::from_reason(format!("Failed to gzip happ bytes: {e}")))?;
    let gz_bytes = enc
        .finish()
        .map_err(|e| napi::Error::from_reason(format!("Failed to finalize gzip: {e}")))?;

    let mut hasher = Sha256::new();
    hasher.update(&gz_bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Compute the legacy happ sha256 for a `.happ` or `.webhapp` file.
///
/// For a webhapp, the inner happ resource is extracted (without unpacking it
/// under the current schema) and the legacy hash is computed over those bytes.
/// For a standalone happ the bytes are used as-is.
#[napi]
pub async fn legacy_happ_sha256_from_path(
    happ_or_webhapp_path: String,
) -> napi::Result<String> {
    let bytes = std::fs::read(&happ_or_webhapp_path).map_err(|e| {
        napi::Error::from_reason(format!(
            "Failed to read {happ_or_webhapp_path}: {e}"
        ))
    })?;
    legacy_happ_sha256_from_bytes(bytes).await
}

/// Compute the legacy happ sha256 from in-memory bytes.
#[napi]
pub async fn legacy_happ_sha256_from_bytes(bytes: Vec<u8>) -> napi::Result<String> {
    let happ_bytes: Vec<u8> = match WebAppBundle::unpack(bytes.as_slice()) {
        Ok(web_app_bundle) => {
            let happ_location = web_app_bundle.manifest().happ_bundle_location();
            let resource_bytes = web_app_bundle
                .get_resource(&happ_location)
                .ok_or_else(|| {
                    napi::Error::from_reason(format!(
                        "Webhapp is missing happ resource at {happ_location}"
                    ))
                })?;
            resource_bytes.as_ref().to_vec()
        }
        Err(_) => bytes,
    };

    legacy_hash_of_happ_bytes(&happ_bytes)
}
