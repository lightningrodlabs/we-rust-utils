#![deny(clippy::all)]

use holochain_types::dna::AgentPubKey;
use holochain_types::prelude::Signature;
use lair_keystore_api::{
    dependencies::sodoken, dependencies::url::Url, ipc_keystore::ipc_keystore_connect, LairClient,
};
use napi::Result;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

struct WeRustHandler {
    lair_client: LairClient,
}

impl WeRustHandler {
    /// Connect to lair keystore
    pub async fn new(keystore_url: String, passphrase: String) -> Self {
        let connection_url_parsed = Url::parse(keystore_url.deref()).unwrap();
        let passphrase_locked_read = Arc::new(Mutex::new(sodoken::LockedArray::from(
            passphrase.as_bytes().to_vec(),
        )));

        // TODO graceful error handling below
        let lair_client = ipc_keystore_connect(connection_url_parsed, passphrase_locked_read)
            .await
            .unwrap();

        Self { lair_client }
    }

    /// Sign a zome call
    pub async fn sign_zome_call(&self, payload: Vec<u8>, pub_key: Vec<u8>) -> Result<Vec<u8>> {
        let pub_key = AgentPubKey::from_raw_39(pub_key);
        let mut pub_key_2 = [0; 32];
        pub_key_2.copy_from_slice(pub_key.get_raw_32());

        let sig = self
            .lair_client
            .sign_by_pub_key(pub_key_2.into(), None, payload.into())
            .await
            .unwrap();

        let signature = Signature(*sig.0);

        Ok(signature.0.to_vec())
    }
}

#[napi(js_name = "WeRustHandler")]
pub struct JsWeRustHandler {
    we_rust_handler: Option<WeRustHandler>,
}

#[napi]
impl JsWeRustHandler {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            we_rust_handler: None,
        }
    }

    #[napi]
    pub async fn connect(keystore_url: String, passphrase: String) -> Self {
        let we_rust_handler = WeRustHandler::new(keystore_url, passphrase).await;

        JsWeRustHandler {
            we_rust_handler: Some(we_rust_handler),
        }
    }

    #[napi]
    pub async fn sign_zome_call(&self, payload: Vec<u8>, pub_key: Vec<u8>) -> Result<Vec<u8>> {
      self
        .we_rust_handler
        .as_ref()
        .unwrap()
        .sign_zome_call(payload, pub_key)
        .await
    }
}
