//! Seeded pure carrier fixtures; no claim of external destruction or finality.
//! (´def:burn:test-support´)
use crate::burn::{
    AcceptedSet, Address, Bootstrap, BurnError, BurnEvidence, BurnInput, BurnRecord, CandidateRule, Encoding, HistoryInput,
    Marker, Opening, OperatorEvidence, PolicyInput, PublicVerifier, RecognizedMarkers, recognize_markers, validate_burn,
    validate_marker_history,
};
use crate::numerics::{ComparisonLimits, ExactLimits, NumericContext};
use std::collections::{BTreeMap, BTreeSet};

/// Fixture verifier binds all public destruction fields and the complete set, without cryptography.
/// (´def:burn:test-support´)
#[derive(Debug)]
pub struct FixtureVerifier;
impl PublicVerifier for FixtureVerifier {
    fn profile(&self) -> &'static str {
        "fixture-public-v1"
    }
    fn destruction(&self, record: &BurnRecord) -> bool {
        record.evidence == proof(record)
    }
    fn opening(&self, commitment: &[u8], opening: &Opening) -> bool {
        let bytes = opening_bytes(&opening.members);
        commitment == bytes && opening.proof == bytes
    }
}
fn proof(record: &BurnRecord) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        record.destruction,
        record.address.0,
        record.amount.exact(),
        record.amount.unit()
    )
    .into_bytes()
}

/// Three marker candidates, with delayed acceptance and one consistent alias.
/// (´def:burn:test-support´)
#[derive(Clone, Debug)]
pub struct BurnCase {
    pub burn: BurnInput,
    pub policy: PolicyInput,
    pub history: HistoryInput,
}

/// Generate a valid fixed-history case from bounded integer words.
/// (´def:burn:test-support´)
/// # Panics
/// Panics only if the reviewed backend cannot construct these small positive rationals.
#[must_use]
pub fn generate(words: &[u64]) -> BurnCase {
    let seed = words.first().copied().unwrap_or(0);
    let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let amount_literal = context.literal(&(seed % 16 + 1).to_string()).unwrap();
    let amount = context.burn(&amount_literal, "burn").unwrap();
    let zero = context.literal("0").unwrap();
    let bootstrap = context.burn(&zero, "burn").unwrap();
    let quarter = context.literal("1/4").unwrap();
    let cost = context.unit_cost(&quarter, "fixture-unit", "burn", "fixture-terms").unwrap();
    let address = Address(format!("address-{}", seed % 7));
    let burn = BurnInput {
        address_space: "opaque-fixture".into(),
        edition: "edition-1".into(),
        sample_convention: "settled-boundary".into(),
        boundary: 2,
        read_addresses: BTreeSet::from([address.clone()]),
        amounts: BTreeMap::from([(address.clone(), amount.clone())]),
        bootstrap: Some(Bootstrap {
            bound: bootstrap,
            empty_interval: true,
            explanation: "external acquisition starts at opening".into(),
        }),
        unit_cost: Some(cost),
        evidence: BurnEvidence {
            edition: "edition-1".into(),
            sample_convention: "settled-boundary".into(),
            settlement_depth: Some(6),
            finality_assumptions: Some("fixture assumption, not chain evidence".into()),
            provenance: Some("public fixture proof profile".into()),
            recording_costs: Some(vec![]),
            operator: Some(OperatorEvidence::Absent {
                explanation: "fixture rules grant no operational accrual".into(),
            }),
        },
    };
    let policy = PolicyInput {
        identity: "policy".into(),
        edition: "1".into(),
        sequence: "sequence".into(),
        published_at: 0,
        genesis_at: 1,
        initial_marker: "m0".into(),
        open_placement: true,
        placement_procedure: "any party submits public evidence".into(),
        cadence: "one candidate per index; no liveness guarantee".into(),
        encoding: Encoding::CompleteList,
        candidate_rule: CandidateRule::UniquePerIndex,
        verification_profile: "fixture-public-v1".into(),
        stability_buffer: 7,
    };
    let mut records = Vec::new();
    for (name, destruction) in [("r0", "d0"), ("r1", "d1"), ("alias", "d0")] {
        let mut record = BurnRecord {
            identity: name.into(),
            destruction: destruction.into(),
            address: address.clone(),
            amount: amount.clone(),
            evidence: vec![],
        };
        record.evidence = proof(&record);
        records.push(record);
    }
    let mut markers = Vec::new();
    for index in 0..=2 {
        let lineage = match index {
            0 => BTreeSet::new(),
            1 => BTreeSet::from(["r0".into(), "r1".into()]),
            _ => records.iter().map(|r| r.identity.clone()).collect(),
        };
        let accepted = match index {
            0 => BTreeSet::new(),
            1 => BTreeSet::from(["r0".into()]),
            _ => lineage.clone(),
        };
        markers.push(Marker {
            name: format!("m{index}"),
            history: "history".into(),
            policy_identity: policy.identity.clone(),
            policy_edition: policy.edition.clone(),
            sequence: policy.sequence.clone(),
            index,
            predecessor: if index == 0 { None } else { Some(format!("m{}", index - 1)) },
            lineage,
            accepted: AcceptedSet::CompleteList(accepted),
            initial_snapshot: if index == 0 { Some(BTreeMap::new()) } else { None },
        });
    }
    BurnCase {
        burn,
        policy,
        history: HistoryInput {
            identity: "history".into(),
            records,
            markers,
        },
    }
}

/// Execute the same public validation/recognition path used by a future host.
/// (´def:burn:test-support´)
/// # Errors
/// Returns publication or evidence validation errors; successful validation returns the recognized prefix and its first candidate refusal without repair.
pub fn recognize(case: BurnCase) -> Result<RecognizedMarkers, BurnError> {
    let burn = validate_burn(case.burn)?;
    let history = crate::validate_history(&[], &[])?;
    let declarations = [crate::Declaration {
        id: crate::DeclarationId {
            namespace: "marker".into(),
            name: "policy".into(),
            edition: 1,
        },
        announced_at: 0,
        effective_at: 0,
    }];
    let records = crate::validate_record(&[], &history, &declarations)?;
    let policy = crate::constants::bind_marker_policy(&records, case.policy, &burn)?;
    let history = validate_marker_history(case.history, &policy, &FixtureVerifier)?;
    Ok(recognize_markers(&history))
}

/// Shared corruption names; consumers own their expected-cause tables.
/// (´def:burn:test-support´)
pub const CORRUPTIONS: &[&str] = &[
    "missing-provenance",
    "missing-finality",
    "missing-costs",
    "missing-operator",
    "empty-bootstrap",
    "sample-gap",
    "late-policy",
    "closed-placement",
    "buffer",
    "wrong-profile",
    "duplicate-record",
    "initial",
    "skipped-index",
    "duplicate-index",
    "lost-predecessor",
    "lost-lineage",
    "regressed-lineage",
    "regressed-acceptance",
    "out-of-lineage",
    "invalid-member",
    "alias-address",
    "alias-amount",
    "history-mix",
    "policy-mix",
    "wrong-encoding",
    "missing-opening",
    "ambiguous-opening",
    "invalid-opening",
    "initial-index",
    "predecessor-name",
    "successor-snapshot",
    "policy-identity",
    "policy-sequence",
    "burn-unit",
    "unexplained-operator",
];

/// Switch the complete set to the fixture's public identity-commitment encoding.
/// The empty set uses a nonempty sentinel; the fixture verifier handles it explicitly.
/// (´def:burn:test-support´)
pub fn committed(case: &mut BurnCase) {
    case.policy.encoding = Encoding::PublicCommitment;
    for marker in &mut case.history.markers {
        let members = match &marker.accepted {
            AcceptedSet::CompleteList(members) => members.clone(),
            _ => BTreeSet::new(),
        };
        let bytes = opening_bytes(&members);
        marker.accepted = AcceptedSet::Commitment {
            commitment: bytes.clone(),
            openings: vec![Opening { members, proof: bytes }],
        };
    }
}
fn opening_bytes(members: &BTreeSet<String>) -> Vec<u8> {
    format!("set:{}", members.iter().cloned().collect::<Vec<_>>().join("|")).into_bytes()
}

/// Corrupt one premise of a valid case; expected refusals belong to each consumer.
/// (´def:burn:test-support´)
/// # Panics
/// Panics only for an unknown roster name or malformed caller fixture; generated cases have three markers and records.
pub fn corrupt(case: &mut BurnCase, name: &str) {
    match name {
        "missing-provenance" => case.burn.evidence.provenance = None,
        "missing-finality" => case.burn.evidence.finality_assumptions = None,
        "missing-costs" => case.burn.evidence.recording_costs = None,
        "missing-operator" => case.burn.evidence.operator = None,
        "empty-bootstrap" => case.burn.bootstrap.as_mut().unwrap().bound = case.history.records[0].amount.clone(),
        "sample-gap" => case.burn.amounts.clear(),
        "late-policy" => case.policy.published_at = case.policy.genesis_at,
        "closed-placement" => case.policy.open_placement = false,
        "buffer" => case.policy.stability_buffer = 6,
        "wrong-profile" => case.policy.verification_profile = "foreign".into(),
        "duplicate-record" => case.history.records.push(case.history.records[0].clone()),
        "initial-index" => {
            for marker in &mut case.history.markers {
                marker.index += 1;
            }
        }
        "predecessor-name" => case.history.markers[2].predecessor = Some("foreign".into()),
        "successor-snapshot" => case.history.markers[2].initial_snapshot = Some(BTreeMap::new()),
        "policy-identity" => case.history.markers[2].policy_identity = "foreign".into(),
        "policy-sequence" => case.history.markers[2].sequence = "foreign".into(),
        "unexplained-operator" => case.burn.evidence.operator = Some(OperatorEvidence::Absent { explanation: " ".into() }),
        "burn-unit" => {
            let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
            let literal = context.literal("1").unwrap();
            for amount in case.burn.amounts.values_mut() {
                *amount = context.burn(&literal, "other-unit").unwrap();
            }
        }
        "initial" => case.history.markers[0].initial_snapshot = None,
        "skipped-index" => case.history.markers[2].index = 3,
        "duplicate-index" => case.history.markers[2].index = 1,
        "lost-predecessor" => {
            case.history.markers.remove(1);
        }
        "lost-lineage" => {
            case.history.records.remove(1);
        }
        "regressed-lineage" => {
            case.history.markers[2].lineage.remove("r1");
        }
        "regressed-acceptance" => case.history.markers[2].accepted = AcceptedSet::CompleteList(BTreeSet::from(["r1".into()])),
        "out-of-lineage" => case.history.markers[1].accepted = AcceptedSet::CompleteList(BTreeSet::from(["alias".into()])),
        "invalid-member" => case.history.records[0].evidence.clear(),
        "alias-address" => {
            let record = &mut case.history.records[2];
            record.address = Address("other".into());
            record.evidence = proof(record);
        }
        "alias-amount" => {
            let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
            let literal = context.literal("100").unwrap();
            let record = &mut case.history.records[2];
            record.amount = context.burn(&literal, "burn").unwrap();
            record.evidence = proof(record);
        }
        "history-mix" => case.history.markers[2].history = "other-history".into(),
        "policy-mix" => case.history.markers[2].policy_edition = "2".into(),
        "wrong-encoding" => case.history.markers[1].accepted = AcceptedSet::WholePrefix,
        "missing-opening" | "ambiguous-opening" | "invalid-opening" => {
            committed(case);
            if let AcceptedSet::Commitment { openings, .. } = &mut case.history.markers[2].accepted {
                match name {
                    "missing-opening" => openings.clear(),
                    "ambiguous-opening" => openings.push(openings[0].clone()),
                    _ => openings[0].proof = vec![0],
                }
            }
        }
        _ => panic!("unknown corruption {name}"),
    }
}
