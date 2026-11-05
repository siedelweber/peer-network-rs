use super::{base, fixture, wire_limits};
use base::d;

fn roundtrip(raw: &d::Disclosure) -> d::Disclosure {
    let bytes = pn_host::publication::encode(raw, &mut base::numeric(), wire_limits()).unwrap();
    let decoded = super::decode_exact(&bytes);
    assert_eq!(&decoded, raw);
    decoded
}

/// Claim: Every package section is retained through canonical decoding, and a changed assertion, omitted cause or mixed cause is refused by the admitted consumer rather than accepted by a decoded flag.
/// ´claim:publication:section-mutations-reach-restoration´
/// ´test:integration:publication-section-mutations´
#[test]
fn publication_section_mutations() {
    let (admitted, check) = fixture::complete();
    let raw = admitted.disclosures();
    let mut cases = Vec::new();
    let mut changed = raw.clone();
    changed.frames[0].sequence.clear();
    cases.push(("accepted sequence", changed));
    let mut changed = raw.clone();
    changed.frames[0].compiled.ledger.counts.clear();
    cases.push(("ledger", changed));
    let mut changed = raw.clone();
    changed.frames[0].compiled.cells.clear();
    cases.push(("semantic projection", changed));
    let mut changed = raw.clone();
    changed.frames[0].compiled.support.products += 1;
    cases.push(("transport", changed));
    let mut changed = raw.clone();
    changed.frames[0].standing.work += 1;
    cases.push(("standing", changed));
    let mut changed = raw.clone();
    changed.frames[0].compiled.title.epoch += 1;
    cases.push(("title", changed));
    let mut changed = raw.clone();
    changed.frames[0].realization.provenance.push(0);
    cases.push(("reproduction", changed));
    let mut changed = raw.clone();
    changed.causes.acts.pop();
    cases.push(("omitted cause", changed));
    let mut changed = raw.clone();
    changed.causes.acts.last_mut().unwrap().id.author = "other-cause".into();
    cases.push(("mixed cause", changed));
    for (name, changed) in cases {
        assert!(d::restore(roundtrip(&changed), &check).is_err(), "{name}");
    }
}

/// Claim: Every named authentication disclosure survives the codec byte for byte; the fixture's retained-cause comparison refuses each substituted field without claiming cryptographic validation.
/// ´claim:publication:authentication-fields-are-untrusted-bytes´
/// ´test:integration:publication-authentication-mutations´
#[test]
fn publication_authentication_mutations() {
    let (admitted, check) = fixture::complete();
    let raw = admitted.disclosures();
    for field in 0..9 {
        let mut changed = raw.clone();
        let auth = &mut changed.causes.acts[0].authentication_evidence;
        match field {
            0 => auth.proposal_precommitment.push(0),
            1 => auth.actor_proposal_signature.push(0),
            2 => auth.content_edition.push('x'),
            3 => auth.dependency_edition.push('x'),
            4 => auth.verified_header.push(0),
            5 => auth.host_seal.push(0),
            6 => auth.approval_binding.push(0),
            7 => auth.authentication_edition.push('x'),
            _ => auth.public_verification_material.push(0),
        }
        assert!(
            d::restore(roundtrip(&changed), &check).is_err(),
            "authentication field {field}"
        );
    }
}

/// Claim: A substituted primitive transcript carried as ridge charge evidence survives byte decoding but is refused by the consumer's fixed ridge replay verifier, rather than by the host fixture's cause attestation.
/// ´claim:publication:ridge-transcript-reaches-fixed-replay´
/// ´test:integration:publication-ridge-transcript-refusal´
#[test]
fn publication_ridge_transcript_refusal() {
    use pn_records::{
        numerics::{Floor, NumericError},
        primitive::Range,
        ridge,
    };
    let (admitted, check) = fixture::complete();
    let mut raw = admitted.disclosures();
    let input = ridge::Inputs {
        definition: ridge::Definition {
            schema: "clean-elasticity-ridge-v1".into(),
            inverse_temperature: "2*ln(2)".into(),
            bleed_squared: "0".into(),
            core_power: "1".into(),
        },
        bracket: Range {
            lower: "1/20".into(),
            upper: "7/100".into(),
        },
        maximum_depth: 2,
        maximum_work: 100_000_000,
        maximum_replay_work: 100_000_000,
    };
    let queries = raw.frames[0]
        .standing
        .rounds
        .iter()
        .flat_map(|round| round.certified.primitives.iter().cloned())
        .collect::<Vec<_>>();
    assert_ne!(queries, Vec::new());
    let evidence = ridge::ChargeEvidence {
        analytic_premises: "clean-ridge-analytic-v1".into(),
        procedure: raw.frames[0].procedure.solve.clone(),
        input: input.clone(),
        record: ridge::Record {
            input,
            queries,
            cells: Vec::new(),
            image: None,
            work: 0,
        },
    };
    raw.frames[0].closure.bindings[0].price.floor = Floor::RidgeImage;
    raw.frames[0].closure.bindings[0].price.ridge = Some(Box::new(evidence));
    assert!(matches!(
        d::restore(roundtrip(&raw), &check),
        Err(pn_epoch::publication::Error::Numeric(NumericError::RidgeEvidence))
    ));
}
