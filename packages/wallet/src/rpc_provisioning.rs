//! Checked public declaration supplied by the provisioning authority.
use crate::{Limits, rpc::RpcRefusal};
use std::collections::BTreeMap;

/// Public run declaration checked against the supported launch profile and raw genesis.
/// (´def:wallet:rpc-provisioning´)
#[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Provisioning {
    /// Exact binary version, checked by the provisioning harness at launch.
    pub binary: String,
    /// Exact Elements chain name, checked by the provisioning harness.
    pub chain: String,
    /// Operator-declared run, compared with the caller's expected run.
    pub run: String,
    /// Complete supported public configuration overrides, excluding credentials and reachability.
    pub parameters: BTreeMap<String, String>,
    /// Nontrivial P2PK signing script; no local signature verification is implied.
    pub challenge: Vec<u8>,
    /// Expected display-order genesis locator.
    pub genesis: [u8; 32],
    /// Expected complete genesis header bytes.
    pub header: Vec<u8>,
}

impl Provisioning {
    pub(crate) fn check(&self, run: &str, limits: Limits) -> Result<(), RpcRefusal> {
        if self.parameters.len() != 13
            || self.parameters.iter().any(|(key, value)| key.len() > 64 || value.len() > 128)
            || self.challenge.len() != 35
            || self.binary.len() > 64
            || self.chain.len() > 32
            || self.run.len() > 128
            || self.header.len() > limits.bytes
        {
            return Err(RpcRefusal::Provisioning);
        }
        let mut actual = serde_json::json!({"binary":self.binary,"chain":self.chain,"run":self.run,
            "parameters":self.parameters,"challenge":self.challenge});
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../provisioning.json")).map_err(|_| RpcRefusal::Provisioning)?;
        // The profile fixes launch parameters, while the caller selects the run.
        actual["run"] = expected["run"].clone();
        if actual != expected || self.run != run || run.is_empty() || run.len() > 128 || self.genesis == [0; 32] {
            return Err(RpcRefusal::Provisioning);
        }
        crate::decoder::decode_header(&self.header, limits).map_err(|_| RpcRefusal::Provisioning)?;
        Ok(())
    }

    pub(crate) fn matches_hash(&self, value: &crate::ReadResult) -> bool {
        matches!(value, crate::ReadResult::Hash(hash) if hash == &self.genesis)
    }
}
