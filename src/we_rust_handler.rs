#![deny(clippy::all)]

use holochain_types::dna::AgentPubKey;
use holochain_types::prelude::Signature;
use lair_keystore_api::{
    dependencies::sodoken, dependencies::url::Url, ipc_keystore::ipc_keystore_connect, LairClient,
};
use napi::Result;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

#[napi]
pub struct WeRustHandler {
    lair_client: LairClient,
}

#[napi]
impl WeRustHandler {
    /// Connect to lair keystore
    #[napi]
    pub async fn connect(keystore_url: String, passphrase: String) -> Result<Self> {
        let connection_url_parsed = Url::parse(keystore_url.deref()).map_err(|e| {
            napi::Error::from_reason(format!("Failed to parse keystore connection URL: {e}"))
        })?;
        let passphrase_locked_read = Arc::new(Mutex::new(sodoken::LockedArray::from(
            passphrase.as_bytes().to_vec(),
        )));

        // TODO graceful error handling below
        let lair_client = ipc_keystore_connect(connection_url_parsed, passphrase_locked_read)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to connect to keystore: {e}")))?;

        Ok(Self { lair_client })
    }

    /// Sign a zome call
    #[napi]
    pub async fn sign_zome_call(&self, payload: Vec<u8>, pub_key: Vec<u8>) -> Result<Vec<u8>> {
        let pub_key = AgentPubKey::from_raw_39(pub_key);
        let mut pub_key_2 = [0; 32];
        pub_key_2.copy_from_slice(pub_key.get_raw_32());

        let sig = self
            .lair_client
            .sign_by_pub_key(pub_key_2.into(), None, payload.into())
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to sign by pubkey: {e}")))?;

        let signature = Signature(*sig.0);

        Ok(signature.0.to_vec())
    }
}
