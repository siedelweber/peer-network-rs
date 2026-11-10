use pn_act_authentication::verification::{VerificationError, VerificationKey};
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}
fn rows() -> Vec<Vec<&'static str>> {
    include_str!("bip340.csv")
        .lines()
        .skip(1)
        .map(|line| line.split(',').collect())
        .collect()
}
/// The unchanged nineteen-row publication is admitted at its original message
/// length: all fifteen 32-byte rows agree with BIP-340, and the four other valid
/// rows refuse by message length. No row is padded or rehashed.
/// ´claim:authentication:published-signatures-have-fixed-message-admission´
/// ´test:integration:published-signatures´
#[test]
fn published_signatures() {
    let rows = rows();
    assert_eq!(rows.len(), 19);
    for index in [18, 5, 0, 14, 9, 3, 16, 1, 11, 7, 4, 12, 2, 17, 6, 10, 15, 8, 13] {
        let row = &rows[index];
        let parsed = VerificationKey::parse(&hex(row[2]));
        if index == 5 || index == 14 {
            assert!(matches!(parsed, Err(VerificationError::InvalidKey)));
            continue;
        }
        let message = hex(row[4]);
        let result = parsed.unwrap().verify(&hex(row[5]), &message);
        let expected = if message.len() != 32 {
            Err(VerificationError::MessageLength)
        } else if row[6] == "TRUE" {
            Ok(())
        } else {
            Err(VerificationError::InvalidSignature)
        };
        assert_eq!(result, expected, "publication row {index}");
    }
}
/// A valid signature is bound to its key and digest, and each boundary exposes
/// the package's typed, content-free refusal instead of binding diagnostics.
/// ´claim:authentication:signature-binds-key-and-message´
/// ´test:integration:signature-association´
#[test]
fn signature_association() {
    let rows = rows();
    let key = VerificationKey::parse(&hex(rows[0][2])).unwrap();
    let other = VerificationKey::parse(&hex(rows[1][2])).unwrap();
    let signature = hex(rows[0][5]);
    let message = hex(rows[0][4]);
    assert_eq!(key.verify(&signature, &message), Ok(()));
    assert_eq!(other.verify(&signature, &message), Err(VerificationError::InvalidSignature));
    let mut changed = message.clone();
    changed[31] ^= 1;
    assert_eq!(key.verify(&signature, &changed), Err(VerificationError::InvalidSignature));
    for error in [
        VerificationError::KeyLength,
        VerificationError::InvalidKey,
        VerificationError::MessageLength,
        VerificationError::SignatureLength,
        VerificationError::ContextCapacity,
        VerificationError::InvalidSignature,
    ] {
        assert!(!error.to_string().contains(rows[0][2]));
        assert!(!format!("{error:?}").contains(rows[0][5]));
    }
}
/// Zero has no curve lift, the field prime and larger x encodings are out of
/// field, and shorter or longer encodings are length errors. The wrapper does
/// not invent a finer native invalid-point class.
/// ´claim:authentication:malformed-x-only-points-refuse´
/// ´test:integration:malformed-points´
#[test]
fn malformed_points() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("malformed-points.json")).unwrap();
    for index in [3, 0, 4, 2, 1] {
        let row = &cases["cases"][index];
        let expected = if row["class"] == "length" {
            VerificationError::KeyLength
        } else {
            VerificationError::InvalidKey
        };
        assert_eq!(
            VerificationKey::parse(&hex(row["encoding"].as_str().unwrap())).unwrap_err(),
            expected
        );
    }
}
