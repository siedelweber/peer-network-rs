//! Independently authored assertions for the selected first-boundary root.
//! (´[ROOT-amend:storage:fixture-replay-interface]´)

use pn_host::storage::{
    DeclarationUse, EpochScope, Family, Payload, Version,
    tree::{Generation, rebuild::AssertedUse},
};
use pn_interchange::{Array, Value};
use pn_records::{
    Declaration, DeclarationContent, DeclarationId, burn,
    constants::{ConstantDefinition, EditionInput},
    numerics::{ComparisonLimits, Floor, NumericContext},
};
use std::collections::{BTreeMap, BTreeSet};

use crate::{base, root};

pub(super) const IDENTITY: [u8; 32] = [
    122, 32, 174, 140, 225, 137, 173, 94, 183, 132, 246, 26, 177, 189, 73, 169, 52, 110, 6, 92, 128, 204, 219, 4, 38, 15, 92,
    198, 119, 183, 110, 169,
];
const IDENTITY_TEXT: &str = "7a20ae8ce189ad5eb784f61ab1bd49a9346e065c80ccdb04260f5cc677b76ea9";

pub(super) fn scope() -> EpochScope {
    EpochScope {
        history: "history".into(),
        policy_identity: "policy".into(),
        policy_edition: "1".into(),
        sequence: "sequence".into(),
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}

fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}

fn declaration_value(declaration: &Declaration) -> Value {
    let content = match &declaration.content {
        DeclarationContent::Opaque => array([Value::Unsigned(0)]),
        DeclarationContent::Deployment { genesis_at } => array([Value::Unsigned(1), text(&genesis_at.to_string())]),
        DeclarationContent::MarkerPolicy { recipe, digest } => {
            array([Value::Unsigned(2), text(recipe), Value::Bytes(digest.to_vec().into())])
        }
    };
    array([
        array([
            text(&declaration.id.namespace),
            text(&declaration.id.name),
            text(&declaration.id.edition.to_string()),
        ]),
        text(&declaration.announced_at.to_string()),
        text(&declaration.effective_at.to_string()),
        content,
    ])
}

fn rule_payload(declaration: &Declaration) -> Payload {
    let encoded = declaration_value(declaration).to_canonical_bytes();
    Payload::rule(&Value::Bytes(encoded.into())).unwrap()
}

fn declaration(namespace: &str, name: &str, content: DeclarationContent, effective_at: u64) -> Declaration {
    Declaration {
        id: DeclarationId {
            namespace: namespace.into(),
            name: name.into(),
            edition: 1,
        },
        announced_at: 0,
        effective_at,
        content,
    }
}

// These are expectation inputs, authored apart from the selected constructor.
fn expected_constants() -> (Declaration, EditionInput) {
    let mut context = NumericContext::new(base::premise_limits(), ComparisonLimits::new(100, 100)).unwrap();
    let one = context.literal("1").unwrap();
    let unit = context.burn_per_action(&one, "burn").unwrap();
    let numeraire = context.numeraire("nu", &unit).unwrap();
    let id = DeclarationId {
        namespace: "numeric".into(),
        name: "constants".into(),
        edition: 1,
    };
    let declaration = Declaration {
        id: id.clone(),
        announced_at: 0,
        effective_at: 1,
        content: DeclarationContent::Opaque,
    };
    let constants = [
        ("one", "1"),
        ("zero", "0"),
        ("negative", "-1/3"),
        ("third", "1/3"),
        ("rest", "2/3"),
        ("hops", "4"),
        ("bleed", "1/400"),
    ]
    .into_iter()
    .map(|(name, value)| ConstantDefinition::Literal {
        name: name.into(),
        value: context.literal(value).unwrap(),
    })
    .collect();
    let edition = EditionInput {
        id,
        floor: Floor::RationalThreeThirtySevenths,
        numeraire,
        formula_edition: "formula".into(),
        controller_edition: "controller".into(),
        constants,
        permitted_overrides: vec![],
        domain_profiles: vec!["declared".into()],
        numerical_procedure: "exact-rational".into(),
        authentication_realization: "declared".into(),
        publication_profile: "internal".into(),
    };
    (declaration, edition)
}

fn expected_destruction(record: &burn::BurnRecord) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        record.destruction,
        record.address.0,
        record.amount.exact(),
        record.amount.unit()
    )
    .into_bytes()
}

fn expected_burn() -> root::BurnCase {
    let mut context = NumericContext::new(base::premise_limits(), ComparisonLimits::new(1_000, 1_000)).unwrap();
    let amount = context.literal("30").unwrap();
    let amount = context.burn(&amount, "burn").unwrap();
    let zero = context.literal("0").unwrap();
    let bootstrap = context.burn(&zero, "burn").unwrap();
    let quarter = context.literal("1/4").unwrap();
    let cost = context.unit_cost(&quarter, "fixture-unit", "burn", "fixture-terms").unwrap();
    let address = burn::Address("a".into());
    let mut record = burn::BurnRecord {
        identity: "r0".into(),
        destruction: "d0".into(),
        address: address.clone(),
        amount: amount.clone(),
        evidence: Vec::new(),
    };
    record.evidence = expected_destruction(&record);
    let policy = burn::PolicyInput {
        identity: "policy".into(),
        edition: "1".into(),
        sequence: "sequence".into(),
        published_at: 0,
        genesis_at: 1,
        initial_marker: "m0".into(),
        open_placement: true,
        placement_procedure: "any party submits public evidence".into(),
        cadence: "one candidate per index; no liveness guarantee".into(),
        encoding: burn::Encoding::CompleteList,
        candidate_rule: burn::CandidateRule::UniquePerIndex,
        verification_profile: "fixture-public-v1".into(),
        stability_buffer: 7,
    };
    let marker =
        |name: &str,
         index: u64,
         history_position: u64,
         predecessor: Option<u64>,
         lineage: BTreeSet<String>,
         accepted: BTreeSet<String>,
         initial_snapshot: Option<BTreeMap<burn::Address, pn_records::numerics::BurnAmount>>| burn::Marker {
            name: name.into(),
            history: "history".into(),
            policy_identity: policy.identity.clone(),
            policy_edition: policy.edition.clone(),
            sequence: policy.sequence.clone(),
            index,
            history_position,
            predecessor,
            lineage,
            accepted: burn::AcceptedSet::CompleteList(accepted),
            initial_snapshot,
        };
    let markers = vec![
        marker("m0", 0, 0, None, BTreeSet::new(), BTreeSet::new(), Some(BTreeMap::new())),
        marker(
            "m1",
            1,
            10,
            Some(0),
            BTreeSet::from(["r0".into()]),
            BTreeSet::from(["r0".into()]),
            None,
        ),
    ];
    root::BurnCase {
        burn: burn::BurnInput {
            address_space: "opaque-fixture".into(),
            edition: "edition-1".into(),
            sample_convention: "settled-boundary".into(),
            boundary: 2,
            read_addresses: BTreeSet::from([address.clone()]),
            amounts: BTreeMap::from([(address, amount)]),
            bootstrap: Some(burn::Bootstrap {
                bound: bootstrap,
                empty_interval: true,
                explanation: "external acquisition starts at opening".into(),
            }),
            unit_cost: Some(cost),
            evidence: burn::BurnEvidence {
                edition: "edition-1".into(),
                sample_convention: "settled-boundary".into(),
                settlement_depth: Some(6),
                finality_assumptions: Some("fixture assumption, not chain evidence".into()),
                provenance: Some("public fixture proof profile".into()),
                recording_costs: Some(vec![]),
                operator: Some(burn::OperatorEvidence::Absent {
                    explanation: "fixture rules grant no operational accrual".into(),
                }),
            },
        },
        policy,
        history: burn::HistoryInput {
            identity: "history".into(),
            records: vec![record],
            markers,
        },
    }
}

fn version(family: Family, key: &str, selected_at: u64, announced_at: u64, opens_at: u64, payload: Payload) -> AssertedUse {
    AssertedUse {
        declaration: DeclarationUse {
            selected_at,
            version: Version {
                family,
                key: key.into(),
                edition: if matches!(family, Family::Rule | Family::Constants) {
                    "1".into()
                } else {
                    IDENTITY_TEXT.into()
                },
                announced_at,
                opens_at,
                payload: Some(payload),
            },
        },
        origin: IDENTITY,
    }
}

// Justified: The independently authored version table remains together for review.
#[expect(clippy::too_many_lines)]
pub(super) fn uses() -> Vec<AssertedUse> {
    let raw = expected_burn();
    let verified_burn = burn::validate_burn(raw.burn.clone()).unwrap();
    let marker_declaration = declaration(
        "marker",
        "policy",
        DeclarationContent::MarkerPolicy {
            recipe: pn_records::constants::MARKER_POLICY_RECIPE.into(),
            digest: pn_records::constants::marker_policy_digest(&raw.policy),
        },
        0,
    );
    let deployment_declaration = declaration("deployment", "genesis", DeclarationContent::Deployment { genesis_at: 1 }, 0);
    let (numeric_declaration, edition) = expected_constants();
    let mut declarations = vec![
        marker_declaration.clone(),
        deployment_declaration.clone(),
        numeric_declaration.clone(),
    ];
    declarations.sort_by_key(|d| (d.id.namespace.len(), d.id.namespace.clone()));
    let empty = pn_records::validate_history(&[], &[]).unwrap();
    let validated = pn_records::validate_record(&[], &empty, &declarations).unwrap();
    let constants = pn_records::constants::bind_constants(&validated, vec![edition]).unwrap();
    let constants = constants.resolve("numeric", "constants", 1).unwrap();
    let policy = pn_records::constants::bind_marker_policy(&validated, raw.policy.clone(), &verified_burn).unwrap();
    let history = burn::validate_marker_history(raw.history, &policy, &root::Check::fixed()).unwrap();

    let mut result = vec![
        version(
            Family::Constants,
            "11:7:history6:policy1:18:sequence7:history6:policy1:18:sequence9:constants7:numeric9:constants",
            1,
            0,
            1,
            Payload::constants(constants).unwrap(),
        ),
        version(
            Family::Rule,
            "11:7:history6:policy1:18:sequence7:history6:policy1:18:sequence11:declaration10:deployment7:genesis",
            1,
            0,
            0,
            rule_payload(&deployment_declaration),
        ),
        version(
            Family::Rule,
            "11:7:history6:policy1:18:sequence7:history6:policy1:18:sequence11:declaration6:marker6:policy",
            1,
            0,
            0,
            rule_payload(&marker_declaration),
        ),
        version(
            Family::Rule,
            "11:7:history6:policy1:18:sequence7:history6:policy1:18:sequence11:declaration7:numeric9:constants",
            1,
            0,
            1,
            rule_payload(&numeric_declaration),
        ),
        version(
            Family::MarkerPolicy,
            concat!(
                "14:7:history6:policy1:18:sequence64:",
                "7a20ae8ce189ad5eb784f61ab1bd49a9346e065c80ccdb04260f5cc677b76ea9",
                "7:history6:policy1:18:sequence18:policy-observation1:1",
                "14:opaque-fixture9:edition-116:settled-boundary"
            ),
            1,
            1,
            1,
            Payload::marker_policy(&policy).unwrap(),
        ),
        version(
            Family::Lineage,
            concat!(
                "17:7:history6:policy1:18:sequence64:",
                "7a20ae8ce189ad5eb784f61ab1bd49a9346e065c80ccdb04260f5cc677b76ea9",
                "7:history6:policy1:18:sequence7:lineage1:1",
                "7:history6:policy1:117:fixture-public-v19:edition-116:settled-boundary"
            ),
            1,
            1,
            1,
            Payload::lineage(&history).unwrap(),
        ),
        version(
            Family::BurnPublication,
            concat!(
                "14:7:history6:policy1:18:sequence64:",
                "7a20ae8ce189ad5eb784f61ab1bd49a9346e065c80ccdb04260f5cc677b76ea9",
                "7:history6:policy1:18:sequence4:burn1:1",
                "14:opaque-fixture9:edition-116:settled-boundary"
            ),
            1,
            1,
            1,
            Payload::burn_publication(&verified_burn).unwrap(),
        ),
        version(
            Family::UnsettledRecognition,
            concat!(
                "17:7:history6:policy1:18:sequence64:",
                "7a20ae8ce189ad5eb784f61ab1bd49a9346e065c80ccdb04260f5cc677b76ea9",
                "7:history6:policy1:18:sequence11:recognition1:1",
                "7:history6:policy1:117:fixture-public-v19:edition-116:settled-boundary"
            ),
            1,
            1,
            1,
            Payload::recognition(&history).unwrap(),
        ),
    ];
    result.sort_by(|a, b| {
        (
            &a.declaration.version.family,
            &a.declaration.version.key,
            &a.declaration.version.edition,
            a.declaration.selected_at,
        )
            .cmp(&(
                &b.declaration.version.family,
                &b.declaration.version.key,
                &b.declaration.version.edition,
                b.declaration.selected_at,
            ))
    });
    result
}

pub(super) fn generation(uses: &[AssertedUse]) -> Generation {
    Generation {
        scope: scope(),
        ordinal: 1,
        minimum: 1,
        label: "unstable".into(),
        versions: uses
            .iter()
            .map(|use_| &use_.declaration.version)
            .filter(|version| matches!(version.family, Family::Rule | Family::Constants))
            .cloned()
            .collect(),
        closures: Vec::new(),
    }
}
