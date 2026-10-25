#![no_main]
#![deny(unsafe_code)]
//! Exercise both bounded public layout entry points with arbitrary public bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = pn_wallet::Limits {
        bytes: 1_048_576,
        items: 1024,
        script: 10_000,
        witness: 65_536,
        allocation: 134_217_728,
    };
    drop(pn_wallet::decode_transaction(data, limits));
    drop(pn_wallet::decode_block(data, limits));
});
