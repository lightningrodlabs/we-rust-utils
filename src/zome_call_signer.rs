#![deny(clippy::all)]

use std::ops::Deref;

use holochain_types::prelude::{Signature, ZomeCallUnsigned};
use lair_keystore_api::{
    dependencies::{sodoken::BufRead, url::Url},
    ipc_keystore::ipc_keystore_connect,
    LairClient,
};
use napi::Result;

use crate::types::*;

struct ZomeCallSigner {
    lair_client: LairClient,
}

impl ZomeCallSigner {
    /// Connect to lair keystore
    pub async fn new(connection_url: String, passphrase: String) -> Result<Self> {
        let connection_url_parsed = Url::parse(connection_url.deref())
            .map_err(|e| napi::Error::from_reason(format!("Failed to parse keystore URL: {e}")))?;

        let passphrase_bufread: BufRead = passphrase.as_bytes().into();

        let lair_client = ipc_keystore_connect(connection_url_parsed, passphrase_bufread)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to connect to keystore: {e}")))?;

        Ok(Self { lair_client })
    }

    /// Sign a zome call
    pub async fn sign_zome_call(
        &self,
        zome_call_unsigned_js: ZomeCallUnsignedNapi,
    ) -> Result<ZomeCallNapi> {
        let zome_call_unsigned: ZomeCallUnsigned = zome_call_unsigned_js.clone().try_into()?;
        let pub_key = zome_call_unsigned.provenance.clone();
        let mut pub_key_2 = [0; 32];
        pub_key_2.copy_from_slice(pub_key.get_raw_32());

        let data_to_sign = zome_call_unsigned.data_to_sign().map_err(|e| {
            napi::Error::from_reason(format!(
                "Failed to get data to sign from unsigned zome call: {e}"
            ))
        })?;

        let sig = self
            .lair_client
            .sign_by_pub_key(pub_key_2.into(), None, data_to_sign)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to sign by pub key: {e}")))?;

        let signature = Signature(*sig.0);

        let signed_zome_call = ZomeCallNapi {
            cell_id: zome_call_unsigned_js.cell_id,
            zome_name: zome_call_unsigned.zome_name.to_string(),
            fn_name: zome_call_unsigned.fn_name.0,
            payload: zome_call_unsigned_js.payload,
            cap_secret: zome_call_unsigned_js.cap_secret,
            provenance: zome_call_unsigned_js.provenance,
            nonce: zome_call_unsigned_js.nonce,
            expires_at: zome_call_unsigned_js.expires_at,
            signature: signature.0.to_vec(),
        };

        Ok(signed_zome_call)
    }
}

#[napi(js_name = "ZomeCallSigner")]
pub struct JsZomeCallSigner {
    zome_call_signer: Option<ZomeCallSigner>,
}

#[napi]
impl JsZomeCallSigner {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            zome_call_signer: None,
        }
    }

    #[napi]
    pub async fn connect(connection_url: String, passphrase: String) -> Result<JsZomeCallSigner> {
        let zome_call_signer = ZomeCallSigner::new(connection_url, passphrase).await?;

        Ok(JsZomeCallSigner {
            zome_call_signer: Some(zome_call_signer),
        })
    }

    #[napi]
    pub async fn sign_zome_call(
        &self,
        zome_call_unsigned_js: ZomeCallUnsignedNapi,
    ) -> Result<ZomeCallNapi> {
        self.zome_call_signer
            .as_ref()
            .ok_or(napi::Error::from_reason("Failed to get reference to ZomeCallSigner"))?
            .sign_zome_call(zome_call_unsigned_js)
            .await
    }
}
