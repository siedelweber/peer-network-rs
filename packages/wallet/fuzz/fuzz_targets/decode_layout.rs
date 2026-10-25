#![no_main]
#![deny(unsafe_code)]
//! Differential codec/adapter acceptance and projection for bounded public bytes.
use libfuzzer_sys::fuzz_target;

fn differential(data: &[u8]) {
    let limits = pn_wallet::Limits { bytes: 4_000_000, items: 4096, script: 10_000, witness: 65_536, allocation: 134_217_728 };
    for block in [false, true] {
        let adapter = if block {
            pn_wallet::decode_block(data, limits)
        } else {
            pn_wallet::decode_transaction(data, limits).map(|tx| pn_wallet::Block { header: Vec::new(), transactions: vec![tx] })
        };
        match pn_wallet::codec_verdict(data, block, limits) {
            Ok((expected, true)) => assert_eq!(adapter, Ok(expected)),
            Ok((_, false)) | Err(_) => assert!(adapter.is_err()),
        }
    }
}

fuzz_target!(|data: &[u8]| { differential(data); });
