use pn_act_authentication::{
    AssetId, KeyHash, QualificationRefusal, RecipeError, initial_asset_id, key_script, qualification_script, signing_key_hash,
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
    assert!(
        assets.iter().any(|row| row["vout"].as_u64().unwrap() != 0),
        "daemon corpus includes a nonzero issuance index"
    );
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

/// The qualification retains the run and consensus prevout unchanged; malformed
/// pushes, flags, versions and lengths have distinct typed refusals.
/// ´claim:authentication:qualification-is-one-canonical-script´
/// ´test:integration:qualification´
#[test]
fn qualification() {
    let mut script = b"\x6a\x4aPNAT\x02".to_vec();
    let run = std::array::from_fn::<_, 32, _>(|i| u8::try_from(i).unwrap());
    let mut prevout = [9; 36];
    prevout[32..].copy_from_slice(&0x0102_0304_u32.to_le_bytes());
    script.extend(run);
    script.extend(prevout);
    script.push(0);
    let value = qualification_script(&script).unwrap();
    let mut wrong_tag_version = script.clone();
    wrong_tag_version[5] ^= 1;
    wrong_tag_version[6] = 3;
    assert_eq!(qualification_script(&wrong_tag_version), Err(QualificationRefusal::Tag));
    assert_eq!(value.run, run);
    assert_eq!(value.prevout, prevout);
    for (at, refusal) in [
        (75, QualificationRefusal::Flags),
        (6, QualificationRefusal::Version),
        (1, QualificationRefusal::Push),
        (0, QualificationRefusal::Push),
        (5, QualificationRefusal::Tag),
    ] {
        let mut bad = script.clone();
        bad[at] ^= 1;
        assert_eq!(qualification_script(&bad), Err(refusal));
    }
    for end in [75, 7, 0] {
        assert_eq!(qualification_script(&script[..end]), Err(QualificationRefusal::Length));
    }
    script.push(0);
    assert_eq!(qualification_script(&script), Err(QualificationRefusal::Length));
    let mut old = b"\x6a\x2aPNAT\x01".to_vec();
    old.extend([7; 32]);
    old.extend([0; 5]);
    assert_eq!(qualification_script(&old), Err(QualificationRefusal::Version));
}
