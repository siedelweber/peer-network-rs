use super::{VerificationError, VerificationKey, membership_key};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Parse,
    Hash,
    Verify,
}
thread_local! { static VISITS: std::cell::RefCell<Vec<Stage>> = const { std::cell::RefCell::new(Vec::new()) }; }
pub(crate) fn visit(stage: Stage) {
    VISITS.with_borrow_mut(|v| v.push(stage));
}
fn take() -> Vec<Stage> {
    VISITS.with_borrow_mut(std::mem::take)
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}
fn valid_key() -> Vec<u8> {
    hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
}

/// Invalid disclosed points and lengths reach no hash or verifier; valid membership
/// computes the existing digest only after point parsing. The counters sit at the
/// called boundaries, not at the caller's proposed ordering.
/// ´claim:authentication:membership-parses-before-hashing´
/// ´test:unit:membership-order´
#[test]
fn membership_order() {
    let _previous = take();
    for bytes in [vec![255; 32], vec![0; 32], vec![1; 31], vec![1; 33]] {
        assert!(membership_key(&bytes).is_err());
        assert_eq!(take(), if bytes.len() == 32 { vec![Stage::Parse] } else { vec![] });
    }
    let bytes = valid_key();
    let (key, digest) = membership_key(&bytes).unwrap();
    assert_eq!(take(), vec![Stage::Parse, Stage::Hash]);
    assert_eq!(format!("{key:?}"), format!("{:?}", VerificationKey::parse(&bytes).unwrap()));
    assert_eq!(digest, crate::signing_key_hash(&bytes).unwrap());
}

/// Message length is checked before signature length and all native calls.
/// In particular a long valid-prefix message is not truncated, and a short
/// message is not hashed to the digest signed by the publication vector.
/// ´claim:authentication:length-admission-precedes-native-verification´
/// ´test:unit:verification-length-order´
#[test]
fn verification_length_order() {
    let key = VerificationKey::parse(&valid_key()).unwrap();
    let _previous = take();
    let signature = hex(include_str!("../../tests/bip340.csv")
        .lines()
        .nth(1)
        .unwrap()
        .split(',')
        .nth(5)
        .unwrap());
    for length in [100, 0, 33, 1, 17, 31] {
        assert_eq!(
            key.verify(&signature, &vec![0; length]),
            Err(VerificationError::MessageLength)
        );
        assert_eq!(take(), []);
    }
    for length in [65, 0, 63] {
        assert_eq!(
            key.verify(&vec![0; length], &[0; 32]),
            Err(VerificationError::SignatureLength)
        );
        assert_eq!(take(), []);
    }
    assert_eq!(key.verify(&[0; 64], &[0; 32]), Err(VerificationError::InvalidSignature));
    assert_eq!(take(), vec![Stage::Verify]);
}
