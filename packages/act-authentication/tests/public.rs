use pn_act_authentication::{
    AssetId, KeyHash, RecipeError, initial_asset_id, key_script, qualification_script, signing_key_hash,
};

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

/// Three daemon-issued identifiers agree in display order with independent
/// `RustCrypto` compression; reversing the input or output fails these values.
/// ´claim:authentication:asset-identifiers-match-daemon´
/// ´test:integration:asset-identifiers´
#[test]
fn asset_identifiers() {
    let values: serde_json::Value = serde_json::from_str(include_str!("golden.json")).unwrap();
    let assets = values["assets"].as_array().unwrap();
    for index in [2, 0, 1] {
        let row = &assets[index];
        let txid = hex(row["prevout"].as_str().unwrap()).try_into().unwrap();
        let contract = hex(row["contract"].as_str().unwrap()).try_into().unwrap();
        let expected = AssetId(hex(row["asset"].as_str().unwrap()).try_into().unwrap());
        assert_eq!(
            initial_asset_id(txid, u32::try_from(row["vout"].as_u64().unwrap()).unwrap(), contract),
            Ok(expected)
        );
    }
    assert_eq!(
        initial_asset_id([0; 32], 0x8000_0000, [0; 32]),
        Err(RecipeError::PrevoutIndex)
    );
}

/// Opaque bytes, including invalid curve encodings, hash as Python hashlib
/// records; only length is refused here. Every script byte is significant.
/// ´claim:authentication:key-hashes-and-scripts-match-independent-values´
/// ´test:integration:key-declarations´
#[test]
fn key_declarations() {
    let values: serde_json::Value = serde_json::from_str(include_str!("golden.json")).unwrap();
    for index in [1, 2, 0] {
        let row = &values["keys"][index];
        let expected = KeyHash(hex(row["digest"].as_str().unwrap()).try_into().unwrap());
        assert_eq!(signing_key_hash(&hex(row["encoding"].as_str().unwrap())), Ok(expected));
        let script = hex(row["script"].as_str().unwrap());
        assert_eq!(key_script(&script), Some(expected));
        for at in [6, 0, 3, 1] {
            let mut bad = script.clone();
            bad[at] ^= 1;
            assert_eq!(key_script(&bad), None);
        }
        assert_eq!(key_script(&script[..38]), None);
        let mut trailing = script;
        trailing.push(0);
        assert_eq!(key_script(&trailing), None);
    }
    for length in [33, 0, 31] {
        assert_eq!(signing_key_hash(&vec![0; length]), Err(RecipeError::KeyLength));
    }
}

/// The qualification retains the run and big-endian input index; all alternate
/// pushes, flags, versions, truncations and trailing bytes qualify nothing.
/// ´claim:authentication:qualification-is-one-canonical-script´
/// ´test:integration:qualification´
#[test]
fn qualification() {
    let mut script = b"\x6a\x2aPNAT\x01".to_vec();
    script.extend([7; 32]);
    script.extend(0x0102_0304_u32.to_be_bytes());
    script.push(0);
    let value = qualification_script(&script).unwrap();
    assert_eq!(value.run, [7; 32]);
    assert_eq!(value.input, 0x0102_0304);
    for at in [43, 6, 1, 0, 5] {
        let mut bad = script.clone();
        bad[at] ^= 1;
        assert_eq!(qualification_script(&bad), None);
    }
    for end in [43, 7, 0] {
        assert_eq!(qualification_script(&script[..end]), None);
    }
    script.push(0);
    assert_eq!(qualification_script(&script), None);
}
