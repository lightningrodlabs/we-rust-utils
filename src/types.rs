use crate::utils::*;
use holochain_types::prelude::{
    AgentPubKey, CapSecret, CellId, DnaHash, ExternIO, FunctionName, Timestamp, ZomeCallUnsigned,
    ZomeName,
};
use napi::Result;

#[derive(Clone)]
#[napi(object)]
pub struct ZomeCallUnsignedNapi {
    pub cell_id: Vec<Vec<u8>>,
    pub zome_name: String,
    pub fn_name: String,
    pub payload: Vec<u8>,
    pub cap_secret: Option<Vec<u8>>,
    pub provenance: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at: i64,
}

impl TryInto<ZomeCallUnsigned> for ZomeCallUnsignedNapi {
    type Error = napi::Error;
    fn try_into(self: Self) -> Result<ZomeCallUnsigned> {
        Ok(ZomeCallUnsigned {
            cell_id: CellId::new(
                DnaHash::from_raw_39(
                    self.cell_id
                        .get(0)
                        .ok_or(napi::Error::from_reason("CellId is of the wrong format."))?
                        .clone(),
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Failed to convert first element of CellId to DnaHash: {e}"
                    ))
                })?,
                AgentPubKey::from_raw_39(
                    self.cell_id
                        .get(1)
                        .ok_or(napi::Error::from_reason("CellId is of the wrong format."))?
                        .clone(),
                )
                .map_err(|e| {
                    napi::Error::from_reason(format!(
                        "Failed to convert second element of CellId to AgentPubKey: {e}"
                    ))
                })?,
            ),
            zome_name: ZomeName::from(self.zome_name),
            fn_name: FunctionName::from(self.fn_name),
            payload: ExternIO::from(self.payload),
            cap_secret: self
                .cap_secret
                .map_or(None, |c| Some(CapSecret::from(vec_to_arr(c)))),
            provenance: AgentPubKey::from_raw_39(self.provenance)
            .map_err(|e| {
                napi::Error::from_reason(format!(
                    "Failed to convert provenance field to AgentPubKey: {e}"
                ))
            })?,
            nonce: vec_to_arr(self.nonce).into(),
            expires_at: Timestamp(self.expires_at),
        })
    }
}

#[napi(object)]
pub struct ZomeCallNapi {
    pub cell_id: Vec<Vec<u8>>,
    pub zome_name: String,
    pub fn_name: String,
    pub payload: Vec<u8>,
    pub cap_secret: Option<Vec<u8>>,
    pub provenance: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at: i64,
    pub signature: Vec<u8>,
}
