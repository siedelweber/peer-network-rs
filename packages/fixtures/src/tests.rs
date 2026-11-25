use super::{Fixture, select};
use pn_host::storage::tree::rebuild::{
    self, AssertedUse, Mismatch, ReplayAssertion, ReplayCause, ReplayEntry, ReplayInput, ReplayPhase, ReplayPreparation,
    ReplayUsage, TargetDisposition,
};
use pn_interchange::{Array, Document, EncodingUsage, Theory, Value, satisfies};

const ROOT_CDDL: &str = r#"e = {0 => "org.peer-network.test.publication", 1 => [1, 0, uint], 2 => [[* any], [* any], [* any]], 3 => [* any], 4 => [* any], 5 => [* any], 6 => [* any], 7 => [* any], 8 => [[* any], [* any], any, [1*1 any]]}"#;

fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned().into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec().into())
}

fn fields(value: &Value) -> &[Value] {
    let Value::Array(value) = value else {
        panic!("expected literal preimage array")
    };
    value.as_slice()
}

fn preimage_context() -> Value {
    let source = include_str!("root_preimage.txt");
    let line = source.lines().find_map(|line| line.strip_prefix("projection_hex=")).unwrap();
    let raw = line
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(raw.len(), 319);
    let preimage = Value::from_canonical_bytes(&raw).unwrap();
    assert_eq!(fields(&preimage)[0], text("PN-result-position-v1"));
    fields(&fields(&preimage)[1])[0].clone()
}

fn family(family: pn_host::storage::Family) -> Value {
    use pn_host::storage::Family;
    Value::Unsigned(match family {
        Family::Constants => 0,
        Family::Rule => 1,
        Family::MarkerPolicy => 2,
        Family::Lineage => 3,
        Family::BurnPublication => 4,
        Family::UnsettledRecognition => 5,
    })
}

fn family_name(family: pn_host::storage::Family) -> &'static str {
    use pn_host::storage::Family;
    match family {
        Family::Constants => "constants",
        Family::Rule => "rule",
        Family::MarkerPolicy => "marker-policy",
        Family::Lineage => "lineage",
        Family::BurnPublication => "burn-publication",
        Family::UnsettledRecognition => "unsettled-recognition",
    }
}

fn version(row: &pn_host::storage::Version) -> Value {
    let payload = row.payload.as_ref().map_or(Value::Null, |payload| {
        let (digest, disclosure) = payload.commitments();
        array([
            family(row.family),
            bytes(payload.bytes()),
            bytes(digest.as_slice()),
            disclosure.map_or(Value::Null, |value| bytes(value.as_slice())),
        ])
    });
    array([
        family(row.family),
        text(&row.key),
        text(&row.edition),
        Value::Unsigned(row.announced_at),
        Value::Unsigned(row.opens_at),
        payload,
    ])
}

// Literal field table composed from the separately authored generation, references,
// result bytes and the reviewed position preimage. It never reads an audit output.
fn expected_debit() -> Vec<u8> {
    let rational = |numerator: &str, denominator: &str| array([text(numerator), text(denominator)]);
    array([
        array([
            array([text("1/4"), rational("1", "4")]),
            array([text("nu"), array([rational("1", "1"), text("burn")])]),
            array([text("1/4"), rational("1", "4")]),
            array([Value::Unsigned(0)]),
            Value::Null,
        ]),
        text("1"),
        array([rational("1", "4"), text("burn")]),
    ])
    .to_canonical_bytes()
}

fn expected_inventory(fixture: &Fixture) -> Value {
    let scope_key = "4:7:history6:policy1:18:sequence";
    let generation = array([
        text(scope_key),
        Value::Unsigned(1),
        Value::Null,
        Value::Unsigned(1),
        text("unstable"),
        array(fixture.generation.versions.iter().map(version)),
        array([]),
    ]);
    let mut history_rows = fixture.uses.iter().collect::<Vec<_>>();
    history_rows.sort_by(|a, b| {
        (
            family_name(a.declaration.version.family),
            &a.declaration.version.key,
            &a.declaration.version.edition,
        )
            .cmp(&(
                family_name(b.declaration.version.family),
                &b.declaration.version.key,
                &b.declaration.version.edition,
            ))
    });
    let histories = history_rows.iter().map(|use_| {
        let row = &use_.declaration.version;
        array([
            version(row),
            array([array([
                text(scope_key),
                Value::Unsigned(1),
                Value::Unsigned(row.opens_at),
                Value::Null,
            ])]),
        ])
    });
    let scope = array([
        text(scope_key),
        preimage_context(),
        array([bytes(&crate::expected::IDENTITY)]),
        array([bytes(&crate::expected::IDENTITY)]),
    ]);
    let mut ordered_uses = fixture.uses.iter().collect::<Vec<_>>();
    ordered_uses.sort_by(|a, b| {
        let a = &a.declaration;
        let b = &b.declaration;
        (
            a.selected_at,
            family_name(a.version.family),
            &a.version.key,
            &a.version.edition,
        )
            .cmp(&(
                b.selected_at,
                family_name(b.version.family),
                &b.version.key,
                &b.version.edition,
            ))
    });
    let selections = ordered_uses.iter().map(|use_| {
        array([
            Value::Unsigned(use_.declaration.selected_at),
            version(&use_.declaration.version),
            bytes(&use_.origin),
        ])
    });
    let debit = expected_debit();
    let complete_debits = [("a", 1, "Registration"), ("a", 2, "Opinion")]
        .into_iter()
        .map(|(author, sequence, family)| {
            array([
                array([text(author), Value::Unsigned(sequence), text(family)]),
                bytes(&crate::expected::IDENTITY),
                bytes(&debit),
            ])
        });
    let result = array([
        text(scope_key),
        bytes(&crate::expected::IDENTITY),
        Value::Null,
        Value::Unsigned(1),
        bytes(fixture.bytes()),
        text("unstable"),
        Value::Unsigned(1),
        array(selections),
        array(complete_debits),
    ]);
    array([array([generation]), array(histories), array([scope]), array([result])])
}

fn counts(value: &Value) -> (usize, usize) {
    match value {
        Value::Text(value) => (value.as_str().len(), 1),
        Value::Bytes(value) => (value.as_slice().len(), 1),
        Value::Array(value) => value
            .as_slice()
            .iter()
            .map(counts)
            .fold((0, 1), |(bytes, slots), (next_bytes, next_slots)| {
                (bytes + next_bytes, slots + next_slots)
            }),
        _ => (0, 1),
    }
}

fn first_difference(actual: &Value, expected: &Value, path: &str) -> Option<String> {
    if actual == expected {
        return None;
    }
    if let (Value::Array(actual), Value::Array(expected)) = (actual, expected) {
        if actual.as_slice().len() != expected.as_slice().len() {
            return Some(format!(
                "{path}: lengths {} and {}",
                actual.as_slice().len(),
                expected.as_slice().len()
            ));
        }
        for (index, (actual, expected)) in actual.as_slice().iter().zip(expected.as_slice()).enumerate() {
            if let Some(diff) = first_difference(actual, expected, &format!("{path}/{index}")) {
                return Some(diff);
            }
        }
    }
    Some(format!(
        "{path}: values differ, actual {:?}, expected {:?}",
        counts(actual),
        counts(expected)
    ))
}

fn prepare_with(
    fixture: &Fixture,
    identity: [u8; 32],
    uses: &[AssertedUse],
) -> Result<rebuild::PreparedReplay, Box<rebuild::ReplayFailure>> {
    let entry = ReplayEntry {
        bytes: fixture.bytes(),
        assertion: ReplayAssertion {
            label: Some("unstable"),
            ordinal: 1,
            scope: crate::expected::scope(),
            identity,
            parent: None,
            depth: 1,
            uses,
        },
    };
    let mut numeric = super::preparation_numeric();
    let mut encoding_usage = EncodingUsage::default();
    let mut reserved = 0usize;
    let mut reserve = |requested: usize| {
        reserved = reserved.checked_add(requested).ok_or(())?;
        if reserved <= 8_192 { Ok(()) } else { Err(()) }
    };
    let mut resources = ReplayPreparation {
        numeric: &mut numeric,
        encoding_usage: &mut encoding_usage,
        reservation: &mut reserve,
        limits: super::preparation_limits(),
        position_ceiling: 4_096,
    };
    rebuild::prepare(
        ReplayInput {
            generations: std::slice::from_ref(&fixture.generation),
            entries: std::slice::from_ref(&entry),
        },
        &fixture.verifier,
        &mut resources,
    )
    .map_err(Box::new)
}

/// Claim: The code-built root satisfies the admitted publication shape and separately authored complete replay assertions under its declared premises; changing one candidate constant, its numeric policy or its arithmetic alone refuses while the unchanged root passes.
/// ´claim:history:fixture-root-correspondence´
/// ´test:unit:fixture-root-correspondence´
#[test]
fn fixture_root_correspondence() {
    let fixture = select("root").unwrap();
    let again = select("root").unwrap();
    assert!(select("other").is_none());
    assert_eq!(fixture.bytes(), again.bytes());
    assert_eq!(fixture.disclosure().frames.len(), 1);
    assert_nested_ceilings(&fixture);
    assert!(Document::from_canonical_bytes(fixture.bytes()).is_ok());
    let theory = Theory::parse(ROOT_CDDL).unwrap();
    let document = Document::from_canonical_bytes(fixture.bytes()).unwrap();
    assert!(satisfies(&document, &theory).holds());
    let decoded = pn_host::publication::decode(
        fixture.bytes(),
        &mut super::preparation_numeric(),
        super::preparation_limits(),
    )
    .unwrap();
    assert_eq!(decoded.frames.len(), 1);
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.counts(), (1, 1));
    assert_eq!(
        prepared.declaration_scopes().collect::<Vec<_>>(),
        vec![&crate::expected::scope()]
    );
    assert_eq!(prepared.commit_order().count(), 1);
    assert_eq!(prepared.reader_order().count(), 1);
    let mut usage = ReplayUsage::default();
    let completed = Fixture::replay_memory(&prepared, &mut usage).unwrap();
    let independently_composed = expected_inventory(&fixture);
    assert_eq!(
        first_difference(completed.inventory().fields(), &independently_composed, "inventory"),
        None
    );
    let (logical_bytes, logical_items) = counts(&independently_composed);
    // Regression count for this selected encoder, never refreshed from its output.
    assert_eq!((logical_bytes, logical_items), (62_101, 390));
    assert_eq!(completed.inventory().counts(), (1, 8, 1, 1, logical_bytes, logical_items));
    let mut reader = completed.reader(super::read_budget());
    let read = reader
        .exact(&crate::expected::scope(), crate::expected::IDENTITY)
        .unwrap()
        .unwrap();
    assert_eq!(read.bytes, fixture.bytes());
    assert_eq!(read.identity, crate::expected::IDENTITY);
    assert_eq!(read.parent, None);
    assert_eq!(read.depth, 1);
    assert_eq!(read.label, "unstable");
    assert_eq!(read.generation, 1);
    assert_eq!(read.selections.len(), fixture.uses.len());
    for (actual, expected) in read.selections.iter().zip(&fixture.uses) {
        assert_eq!(actual.use_, &expected.declaration);
        assert_eq!(actual.origin, expected.origin);
    }
    assert_eq!(read.debits.len(), 2);
    for (actual, (sequence, family)) in read.debits.iter().zip([(1, "Registration"), (2, "Opinion")]) {
        assert_eq!(actual.vintage.key.scope, crate::expected::scope());
        assert_eq!(actual.vintage.key.act.author, "a");
        assert_eq!(actual.vintage.key.act.sequence, sequence);
        assert_eq!(actual.vintage.key.act.family, family);
        assert_eq!(actual.origin, crate::expected::IDENTITY);
        assert_eq!(actual.bytes, expected_debit());
    }
    assert_eq!(
        reader.as_of(&crate::expected::scope(), crate::expected::IDENTITY, 0).unwrap(),
        None
    );
    assert!(
        reader
            .as_of(&crate::expected::scope(), crate::expected::IDENTITY, 1)
            .unwrap()
            .is_some()
    );

    assert_independence_neighbors(&fixture);
}

fn assert_nested_ceilings(fixture: &Fixture) {
    let published = &fixture.disclosure().frames[0].procedure;
    assert_eq!(published.solve.maximum_work, 100_000_000);
    assert_eq!(published.solve.maximum_solve_work, 100_000_000);
    assert_eq!(published.solve.maximum_replay_work, 100_000_000);
    assert_eq!(published.solve.maximum_iterations, 20);
    let enclosure = published.solve.enclosure.as_ref().unwrap();
    for limits in [&enclosure.store, &enclosure.operation] {
        assert_eq!(limits.work, 100_000_000);
        assert_eq!(limits.output_bytes, 32 * 1024 * 1024);
        assert_eq!(limits.arithmetic_steps, 5_000_000);
    }
    assert_eq!(enclosure.operation, enclosure.store);
    let refinement = &enclosure.refinement;
    assert_eq!(refinement.version, 1);
    assert_eq!(refinement.precision, 4);
    assert_eq!(refinement.grid_ceiling, 96);
    assert_eq!(refinement.rounds, 1);
    assert_eq!(refinement.reduction_ceiling, 4);
    assert_eq!(refinement.term_ceiling, 64);
    assert_eq!(refinement.checking_work, 0);
    assert_eq!(published.maximum_products, 10_000);
    assert_eq!(published.arithmetic, crate::base::premise_limits());
    assert_eq!(fixture.disclosure().numeric.comparison_attempts, 4);
    assert_eq!(fixture.disclosure().numeric.comparison_work, 100_000_000);
    assert_eq!(fixture.disclosure().numeric.arithmetic, crate::base::premise_limits());
    assert_eq!(
        fixture.disclosure().frames[0].next.declaration.refinement.precision_bits,
        vec![4]
    );
    assert_eq!(
        fixture.disclosure().frames[0].next.declaration.refinement.maximum_work,
        100_000_000
    );
    assert_eq!(
        fixture.disclosure().frames[0].next.declaration.refinement.maximum_replay_work,
        100_000_000
    );
    assert_eq!(
        fixture.disclosure().frames[0].next.publications[0]
            .proposal
            .search
            .maximum_steps,
        8
    );
}

fn assert_independence_neighbors(fixture: &Fixture) {
    // A candidate-only constant change cannot alter the separately authored selected use.
    let (changed_closed, changed_carrier, changed_verifier) = crate::root::altered_constant_fixture();
    let changed_admitted = pn_epoch::publication::assemble(&changed_closed, changed_carrier, &changed_verifier).unwrap();
    let changed_disclosure = changed_admitted.disclosures();
    let mut numeric = super::encoding_numeric();
    let changed_bytes = pn_host::publication::encode(&changed_disclosure, &mut numeric, super::encoding_limits()).unwrap();
    assert_ne!(changed_bytes, fixture.bytes());
    let changed_uses = crate::expected::uses();
    let changed_fixture = Fixture {
        disclosure: changed_disclosure,
        bytes: changed_bytes,
        verifier: changed_verifier,
        generation: crate::expected::generation(&changed_uses),
        uses: changed_uses,
    };
    let changed = prepare_with(&changed_fixture, crate::expected::IDENTITY, &changed_fixture.uses)
        .err()
        .unwrap();
    assert_eq!(changed.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(changed.cause, ReplayCause::Mismatch(Mismatch::References)));
    assert!(prepare_with(fixture, crate::expected::IDENTITY, &fixture.uses).is_ok());

    // The fixed verifier premise refuses candidate policy and arithmetic changes.
    let (closed, mut carrier, check) = crate::root::fixture();
    carrier.numeric.comparison_work += 1;
    assert!(matches!(
        pn_epoch::publication::assemble(&closed, carrier, &check),
        Err(pn_epoch::publication::Error::Structure("publication profile"))
    ));
    let (closed, mut carrier, check) = crate::root::fixture();
    carrier.frames[0].procedure.arithmetic.work += 1;
    assert!(matches!(
        pn_epoch::publication::assemble(&closed, carrier, &check),
        Err(pn_epoch::publication::Error::Structure("publication profile"))
    ));
    assert!(select("root").is_some());
}

/// Claim: Changed identity and selected-version-coordinate assertions refuse with distinct pre-write causes under fixed candidate bytes and premises.
/// ´claim:history:fixture-root-independent-assertions´
/// ´test:unit:fixture-root-independent-assertions´
#[test]
fn fixture_root_independent_assertions() {
    let fixture = select("root").unwrap();
    let mut wrong_identity = crate::expected::IDENTITY;
    wrong_identity[0] ^= 1;
    let refused = prepare_with(&fixture, wrong_identity, &fixture.uses).err().unwrap();
    assert_eq!(refused.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(refused.cause, ReplayCause::Mismatch(Mismatch::Identity)));
    assert_eq!(refused.disposition, TargetDisposition::NotTouched);

    let mut wrong_coordinate = fixture.uses.clone();
    wrong_coordinate[0].declaration.selected_at += 1;
    let refused = prepare_with(&fixture, crate::expected::IDENTITY, &wrong_coordinate)
        .err()
        .unwrap();
    assert_eq!(refused.phase, ReplayPhase::PrewriteComparison);
    assert!(matches!(refused.cause, ReplayCause::Mismatch(Mismatch::Coordinates)));
    assert_eq!(refused.disposition, TargetDisposition::NotTouched);
    assert!(prepare_with(&fixture, crate::expected::IDENTITY, &fixture.uses).is_ok());
}

/// Claim: The fixture-name membership check and selection agree with the declared closed set and the selected absent-name neighbours.
/// ´claim:history:fixture-name-membership-matches-selection´
/// ´test:unit:fixture-name-membership-matches-selection´
#[test]
fn fixture_name_membership_matches_selection() {
    for (name, expected) in [
        ("root", true),
        ("", false),
        ("other", false),
        ("Root", false),
        (" root", false),
        ("root ", false),
        ("root\0", false),
        ("rooté", false),
    ] {
        assert_eq!(crate::recognizes_name(name), expected, "membership: {name:?}");
        assert_eq!(select(name).is_some(), expected, "selection: {name:?}");
    }
}
