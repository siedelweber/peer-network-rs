//! Bounded public Elements layouts under (´[ROOT-amend:devnet:wallet-decoder]´).
//! No network, RPC, signing or proof-verification interface is exposed.

mod decoder;
pub use decoder::{
    Block, Input, Limits, Output, Refusal, Transaction, TransactionFields, decode_block, decode_transaction, evidence_amount,
};
