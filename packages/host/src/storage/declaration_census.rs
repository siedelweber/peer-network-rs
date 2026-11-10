//! Independent storage correspondence census over decoded public disclosures.
//! (´[ROOT-amend:storage:admitted-correspondence]´)
use super::super::admitted_result::{AdmittedEpoch, EpochScope};
use super::{Family, Payload};
use pn_epoch::publication::disclosures as d;
use pn_records::{DeclarationId, numerics::NumericContext};
use std::collections::BTreeMap;
use std::fmt::Write;

type Coordinate = (Family, String, String, u64);
type Expected = BTreeMap<Coordinate, (u64, u64, Payload)>;

fn numeric() -> NumericContext {
    NumericContext::new(d::Limits::default(), pn_records::numerics::ComparisonLimits::new(1000, 1000)).unwrap()
}

fn limits() -> d::Limits {
    d::Limits {
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        ..d::Limits::default()
    }
}

fn fixture() -> &'static (pn_epoch::publication::AdmittedPackage, pn_epoch::test_support::Check) {
    static FIXTURE: std::sync::OnceLock<(pn_epoch::publication::AdmittedPackage, pn_epoch::test_support::Check)> =
        std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (mut raw, verifier) = pn_epoch::test_support::ridge_disclosures();
        raw.causes.declarations.push(pn_records::Declaration {
            id: DeclarationId {
                namespace: "unused".into(),
                name: "not-selected".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: pn_records::DeclarationContent::Opaque,
        });
        raw.causes.acts.sort_by_key(|a| std::cmp::Reverse(a.id.clone()));
        raw.causes.declarations.reverse();
        assert!(
            !raw.causes.declarations.windows(2).all(|p| p[0].id < p[1].id),
            "declaration causes must reach restoration unsorted"
        );
        assert!(
            !raw.causes.acts.windows(2).all(|p| p[0].id < p[1].id),
            "census input must reach restoration unsorted"
        );
        (d::restore(raw, &verifier).unwrap(), verifier)
    })
}

fn framed(scope: &EpochScope, suffix: &[&str]) -> String {
    let mut fields = vec![
        scope.history.as_str(),
        &scope.policy_identity,
        &scope.policy_edition,
        &scope.sequence,
    ];
    fields.extend_from_slice(suffix);
    let mut text = String::new();
    write!(text, "{}:", fields.len()).unwrap();
    for field in fields {
        write!(text, "{}:{field}", field.len()).unwrap();
    }
    text
}

fn array(v: &pn_interchange::Value) -> &[pn_interchange::Value] {
    let pn_interchange::Value::Array(items) = v else {
        panic!("canonical array")
    };
    items.as_slice()
}

fn reference<'a>(
    out: &mut Vec<(&'a DeclarationId, u64)>,
    hits: &mut BTreeMap<&'static str, usize>,
    branch: &'static str,
    id: &'a DeclarationId,
    at: u64,
) {
    out.push((id, at));
    *hits.entry(branch).or_default() += 1;
}

// The census first enumerates typed selection coordinates from the correspondence
// table, then joins the public declaration table. It does not ask the carrier
// which declarations were selected or use its projection helpers.
fn references(raw: &d::Disclosure) -> (Vec<(&DeclarationId, u64)>, BTreeMap<&'static str, usize>) {
    let mut refs = Vec::new();
    let mut hits = BTreeMap::new();
    for f in &raw.frames {
        for (namespace, name, tag) in [("marker", "policy", "marker"), ("deployment", "genesis", "deployment")] {
            let at = f.marker_policy.genesis_at;
            let selected = raw
                .causes
                .declarations
                .iter()
                .filter(|r| r.id.namespace == namespace && r.id.name == name && r.effective_at <= at)
                .max_by_key(|r| r.effective_at)
                .unwrap();
            reference(&mut refs, &mut hits, tag, &selected.id, at);
        }
        let mut parameter_sets = vec![("frame-parameters", "frame-profiles", &f.parameters)];
        parameter_sets.extend(
            f.closure
                .bindings
                .iter()
                .map(|b| ("binding-parameters", "binding-profiles", &b.inputs.parameters)),
        );
        for (parameters, profiles, p) in parameter_sets {
            reference(&mut refs, &mut hits, parameters, &p.edition, p.boundary);
            for profile in &p.profiles {
                reference(&mut refs, &mut hits, profiles, &profile.edition, p.boundary);
            }
        }
        reference(
            &mut refs,
            &mut hits,
            "base",
            &f.compiled.base.edition,
            f.compiled.base.boundary,
        );
        let mut procedures = vec![("solve", &f.procedure.solve)];
        for (tag, price) in std::iter::once(("frame-price", &f.price))
            .chain(f.closure.bindings.iter().map(|b| ("binding-price", &b.price)))
            .chain(f.compiled.ledger.debits.values().map(|b| ("debit-price", &b.price)))
        {
            if let Some(ridge) = &price.ridge {
                procedures.push((tag, &ridge.procedure));
            }
        }
        for (tag, schedule) in [("led-schedule", &f.closure.schedule), ("next-schedule", &f.next)] {
            procedures.extend(schedule.publications.iter().map(|p| (tag, &p.proposal.controller.procedure)));
        }
        for (tag, p) in procedures {
            reference(&mut refs, &mut hits, tag, &p.edition, p.boundary);
        }
        let records = std::iter::once(("standing-proposal", "standing-certified", &f.standing)).chain(
            f.closure
                .final_gates
                .standing
                .iter()
                .map(|s| ("final-proposal", "final-certified", s)),
        );
        for (proposal, certified, record) in records {
            for round in &record.rounds {
                reference(
                    &mut refs,
                    &mut hits,
                    certified,
                    &round.certified.edition,
                    round.certified.boundary,
                );
                for p in &round.proposals {
                    reference(&mut refs, &mut hits, proposal, &p.edition, p.boundary);
                }
            }
        }
    }
    (refs, hits)
}

fn expected(
    raw: &d::Disclosure,
    scope: &EpochScope,
    terminal: u64,
    document: &pn_interchange::Document,
    verifier: &pn_epoch::test_support::Check,
) -> Expected {
    let mut output = Expected::new();
    let (references, hits) = references(raw);
    for branch in [
        "marker",
        "deployment",
        "frame-parameters",
        "frame-profiles",
        "binding-parameters",
        "binding-profiles",
        "base",
        "solve",
        "frame-price",
        "binding-price",
        "debit-price",
        "led-schedule",
        "next-schedule",
        "standing-proposal",
        "standing-certified",
        "final-proposal",
        "final-certified",
    ] {
        assert!(
            hits.get(branch).is_some_and(|count| *count > 0),
            "unreached correspondence branch {branch}"
        );
    }
    for (id, at) in references {
        let Some(row) = raw.causes.declarations.iter().find(|r| &r.id == id) else {
            continue;
        };
        // The published declaration's complete canonical item is the Rule payload.
        let encoded = array(&array(document.content().get(8).unwrap())[0])
            .iter()
            .find(|v| {
                let fields = array(&array(v)[0]);
                fields
                    == [
                        pn_interchange::Value::Text(id.namespace.clone().into()),
                        pn_interchange::Value::Text(id.name.clone().into()),
                        pn_interchange::Value::Text(id.edition.to_string().into()),
                    ]
            })
            .unwrap();
        let payload = Payload::rule(&pn_interchange::Value::Bytes(encoded.to_canonical_bytes().into())).unwrap();
        output.insert(
            (
                Family::Rule,
                framed(scope, &["declaration", &id.namespace, &id.name]),
                id.edition.to_string(),
                at,
            ),
            (row.announced_at, row.effective_at, payload),
        );
    }
    output.extend(non_rule_rows(raw, scope, terminal, verifier));
    output
}

fn non_rule_rows(raw: &d::Disclosure, scope: &EpochScope, terminal: u64, verifier: &pn_epoch::test_support::Check) -> Expected {
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let declarations = pn_records::validate_record(&[], &empty, &raw.causes.declarations).unwrap();
    let constants = pn_records::constants::bind_constants(&declarations, raw.causes.editions.clone()).unwrap();
    let mut output = Expected::new();
    for f in &raw.frames {
        for binding in &f.closure.bindings {
            let p = &binding.inputs.parameters;
            let row = raw.causes.declarations.iter().find(|r| r.id == p.edition).unwrap();
            let bound = pn_epoch::bind_inputs(&constants, p.clone(), d::Limits::default()).unwrap();
            let payload = Payload::constants(bound.constants()).unwrap();
            output.insert(
                (
                    Family::Constants,
                    framed(scope, &["constants", &p.edition.namespace, &p.edition.name]),
                    p.edition.edition.to_string(),
                    p.boundary,
                ),
                (row.announced_at, row.effective_at, payload),
            );
        }
        let burn = pn_records::burn::validate_burn(f.burn.clone()).unwrap();
        let policy = pn_records::constants::bind_marker_policy(&declarations, f.marker_policy.clone(), &burn).unwrap();
        let lineage = pn_records::burn::validate_marker_history(f.marker_history.clone(), &policy, verifier).unwrap();
        let b = f.parameters.boundary.to_string();
        let basis = &f.closure.markers.basis;
        for (family, kind, payload) in [
            (
                Family::MarkerPolicy,
                "policy-observation",
                Payload::marker_policy(&policy).unwrap(),
            ),
            (Family::BurnPublication, "burn", Payload::burn_publication(&burn).unwrap()),
            (Family::Lineage, "lineage", Payload::lineage(&lineage).unwrap()),
            (
                Family::UnsettledRecognition,
                "recognition",
                Payload::recognition(&lineage).unwrap(),
            ),
        ] {
            let mut suffix = vec![kind, &b];
            if matches!(family, Family::MarkerPolicy | Family::BurnPublication) {
                suffix.extend([f.burn.address_space.as_str(), &f.burn.edition, &f.burn.sample_convention]);
            } else {
                suffix.extend([
                    basis.history.as_str(),
                    &basis.policy_identity,
                    &basis.policy_edition,
                    &basis.verifier_profile,
                    &basis.burn_publication_edition,
                    &basis.sample_convention,
                ]);
            }
            output.insert(
                (family, framed(scope, &suffix), terminal.to_string(), terminal),
                (terminal, terminal, payload),
            );
        }
    }
    output
}

/// Claim: A decoded ridge-bearing public package independently enumerates every declaration-selection branch and compares all six storage families coordinate by coordinate with the admitted carrier, without treating unselected causes as selections.
/// ´claim:history:admitted-declaration-census-covers-nested-references´
/// ´test:unit:admitted-declaration-census´
#[test]
fn admitted_declaration_census() {
    let (package, verifier) = fixture();
    let carrier = AdmittedEpoch::from_package(package, &mut numeric(), limits()).unwrap();
    let decoded = crate::publication::decode(carrier.bytes(), &mut numeric(), limits()).unwrap();
    let document = pn_interchange::Document::from_canonical_bytes(carrier.bytes()).unwrap();
    let expected = expected(
        &decoded,
        &carrier.event().scope,
        carrier.event().boundary,
        &document,
        verifier,
    );
    let actual: Expected = carrier
        .declarations()
        .iter()
        .map(|u| {
            let v = &u.version;
            (
                (v.family, v.key.clone(), v.edition.clone(), u.selected_at),
                (v.announced_at, v.opens_at, v.payload.clone().unwrap()),
            )
        })
        .collect();
    assert_eq!(
        actual, expected,
        "independent declaration census differs by coordinate or complete payload"
    );
    assert_eq!(actual.keys().map(|k| k.0).collect::<std::collections::BTreeSet<_>>().len(), 6);
}
