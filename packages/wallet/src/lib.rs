//! Bounded public Elements layouts under (´[ROOT-amend:devnet:wallet-decoder]´).
//! Closed secret-owning RPC reads do not expose signing or proof verification.

mod decoder;
mod rpc;
mod rpc_cookie;
mod rpc_http;
mod rpc_json;
mod rpc_provisioning;
mod rpc_secret;
pub use decoder::{
    Block, Input, Limits, Output, Refusal, Transaction, TransactionFields, decode_block, decode_transaction, evidence_amount,
};
pub use rpc::{Read, ReadResult, RpcClient, RpcConfig, RpcLimits, RpcLink, RpcRefusal};
pub use rpc_provisioning::Provisioning;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use decoder::codec_verdict;
