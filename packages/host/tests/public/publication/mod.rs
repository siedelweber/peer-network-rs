//! Host-owned byte and restoration controls, with a declared fixture verifier.
#[path = "base.rs"]
mod base;
#[path = "fixture.rs"]
mod fixture;
mod golden;
#[path = "mutations.rs"]
mod mutations;
#[path = "refusals.rs"]
mod refusals;

/// Claim: Canonical publication bytes retain the complete two-boundary disclosure and restore the same admitted package under a declared host-side fixture verifier; byte decoding alone conveys no admission or cryptographic authority.
/// ´claim:publication:canonical-disclosure-roundtrip´
/// ´test:integration:publication-codec-roundtrip´
#[test]
fn publication_codec_roundtrip() {
    pn_interchange::Theory::parse(include_str!("../../../src/publication/publication.cddl")).unwrap();
    let (admitted, check) = fixture::complete();
    let raw = admitted.disclosures();
    let bytes = pn_host::publication::encode(&raw, &mut base::numeric(), wire_limits()).unwrap();
    let decoded = decode_exact(&bytes);
    assert_eq!(decoded, raw);
    let mut shuffled = raw.clone();
    shuffled.causes.acts.reverse();
    shuffled.causes.declarations.reverse();
    assert_eq!(
        pn_host::publication::encode(&shuffled, &mut base::numeric(), wire_limits()).unwrap(),
        bytes
    );
    let mut reordered = raw.clone();
    assert!(reordered.frames[0].sequence.len() > 1);
    reordered.frames[0].sequence.reverse();
    let reordered_bytes = pn_host::publication::encode(&reordered, &mut base::numeric(), wire_limits()).unwrap();
    assert_eq!(decode_exact(&reordered_bytes), reordered);
    assert_ne!(
        pn_host::publication::encode(&reordered, &mut base::numeric(), wire_limits()).unwrap(),
        bytes
    );
    let mut duplicate = raw.clone();
    duplicate.causes.acts.push(raw.causes.acts[0].clone());
    assert!(matches!(
        pn_host::publication::encode(&duplicate, &mut base::numeric(), wire_limits()),
        Err(pn_host::publication::Error::Order)
    ));
    let restored = base::d::restore(decoded, &check).unwrap();
    assert_eq!(restored.carrier(), admitted.carrier());
    assert_eq!(restored.boundary().evidence(), admitted.boundary().evidence());
}

fn decode_exact(bytes: &[u8]) -> base::d::Disclosure {
    let decoded = pn_host::publication::decode(bytes, &mut base::numeric(), wire_limits()).unwrap();
    assert_eq!(
        pn_host::publication::encode(&decoded, &mut base::numeric(), wire_limits()).unwrap(),
        bytes
    );
    decoded
}

fn wire_limits() -> base::Limits {
    base::Limits {
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        ..base::Limits::default()
    }
}
