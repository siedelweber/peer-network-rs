mod common;
#[path = "common/joined.rs"]
mod joined;
use joined::{Verifier, act, anchors, coordinates, id, numeric, package, settlement};
use nrz_cas::limits::Limits;
use pn_epoch::{
    base::BaseScore,
    compiler::{CoefficientEvidence, CompileError, CompiledState, compile_final_state},
    support::SupportError,
};
use pn_records::{CandidateAct, SettlementReferences, burn::Address};
use std::collections::{BTreeMap, BTreeSet};

const BURNS: [(&str, &str); 3] = [("seller", "100"), ("buyer", "100"), ("third", "100")];

fn compile(acts: &[CandidateAct], boundary: u64) -> CompiledState {
    let result = compile_final_state(
        &package(acts, boundary, &BURNS),
        &Verifier,
        &mut numeric(),
        Limits::default(),
        1000,
    );
    assert!(result.is_ok(), "{result:?}; acts={acts:?}");
    result.unwrap()
}

// Independent literal oracle: no production grouping, resolution, coefficient or
// sparse assembly operation is called. Each row describes one singleton cell.
const FAMILIES: [(&str, &[&str], &str); 19] = [
    ("Registration", &[], "seller"),
    ("Publish", &["attachment"], "seller"),
    ("Owner", &["attachment"], "seller"),
    ("Affinity", &["association", "attraction"], "seller"),
    ("Opinion", &["polarity", "reaction"], "buyer"),
    ("Reference", &["effort", "enthusiasm"], "buyer"),
    ("Review", &["effort", "enthusiasm"], "seller"),
    ("Tag", &["confidence", "relevance"], "seller"),
    ("Participant", &["interactivity", "responsibility"], "seller"),
    ("Send", &["importance"], "seller"),
    ("Bid", &["generosity", "urgency"], "seller"),
    ("Join Request", &["formality", "urgency"], "seller"),
    ("Invitation", &["formality", "urgency"], "buyer"),
    ("Accept", &["comfort", "equity"], "seller"),
    ("Ratify", &["comfort", "equity"], "seller"),
    ("Withdraw", &[], "seller"),
    ("Rescind", &[], "seller"),
    ("Leave", &[], "seller"),
    ("De-invite", &[], "seller"),
];

fn family_case(family: &str) -> Vec<CandidateAct> {
    let mut acts = anchors();
    let mut input = act(family, "seller", 10, 1);
    input.body.settlement = match family {
        "Accept" => Some(SettlementReferences::Accept {
            settles: acts[0].id.clone(),
        }),
        "Ratify" => Some(SettlementReferences::Ratify {
            settles: acts[0].id.clone(),
            accepts: acts[1].id.clone(),
        }),
        _ => None,
    };
    acts.push(input);
    acts
}

fn ledger_table(state: &CompiledState, rows: &[(&str, u64, &str, &str)]) {
    let view = state.view();
    assert_eq!(view.ledger.counts.len(), rows.len());
    for (author, count, balance, rate) in rows {
        let address = Address((*author).into());
        assert_eq!(view.ledger.counts[&address].0, *count);
        assert_eq!(view.ledger.balances[&address].exact(), *balance);
        assert_eq!(view.support.sources[*author].reduced_rate, *rate);
        assert_eq!(view.support.sources[*author].emission, "1");
        assert_eq!(view.support.sources[*author].retained, "0");
        assert_eq!(view.ledger.snapshots[0].gross[&address].exact(), "100");
        assert_eq!(view.ledger.snapshots[0].increment[&address].exact(), "100");
    }
    assert_eq!(
        view.ledger.debits.len(),
        rows.iter().map(|(_, n, _, _)| usize::try_from(*n).unwrap()).sum()
    );
    for debit in view.ledger.debits.values() {
        assert_eq!(debit.charged().exact(), "2");
    }
}

fn base_table(state: &CompiledState, rows: &[(&str, &str, &str)]) {
    let actual: BTreeMap<_, _> = state
        .view()
        .base
        .rows
        .iter()
        .flat_map(|(source, row)| {
            row.iter()
                .map(move |(target, entry)| ((source.as_str(), target.as_str()), entry.score.clone()))
        })
        .collect();
    let expected: BTreeMap<_, _> = rows
        .iter()
        .map(|(s, t, v)| ((*s, *t), BaseScore::Exact((*v).into())))
        .collect();
    assert_eq!(actual, expected);
}

fn family_table(family: &str, names: &[&str], recipient: &str, state: &CompiledState) {
    let view = state.view();
    assert_eq!(state.package().input().history.acts().len(), 4);
    assert_eq!(view.cells.len(), 4);
    assert_eq!(view.coefficients.len(), 4);
    assert_eq!(view.recipients.len(), 4);
    let identity = id(family, "seller", 10);
    let row = view
        .recipients
        .iter()
        .find(|row| row.cell.members.contains(&identity))
        .unwrap();
    assert_eq!(row.cell.members, BTreeSet::from([identity]));
    assert_eq!(row.recipient, recipient);
    let expected: BTreeMap<_, _> = names.iter().map(|name| ((*name).into(), "1".into())).collect();
    assert_eq!(row.cell.coordinates, expected);
    for cell in &view.cells {
        assert_eq!(view.coefficients[&cell.identity], CoefficientEvidence::Exact("1".into()));
    }
    ledger_table(
        state,
        &[("seller", 2, "96", "48"), ("buyer", 1, "98", "98"), ("third", 1, "98", "98")],
    );
    if recipient == "buyer" {
        base_table(
            state,
            &[
                ("seller", "seller", "2"),
                ("seller", "buyer", "1"),
                ("buyer", "buyer", "2"),
                ("third", "third", "2"),
            ],
        );
    } else {
        base_table(
            state,
            &[("seller", "seller", "3"), ("buyer", "buyer", "2"), ("third", "third", "2")],
        );
    }
    let self_set = |author: &str| BTreeSet::from([author.to_owned()]);
    let seller = if recipient == "buyer" {
        BTreeSet::from(["seller".into(), "buyer".into()])
    } else {
        self_set("seller")
    };
    let expected = BTreeMap::from([
        ("seller".into(), seller),
        ("buyer".into(), self_set("buyer")),
        ("third".into(), self_set("third")),
    ]);
    assert_eq!(view.support.by_depth, BTreeMap::from([(1, expected.clone())]));
    assert_eq!(view.support.emitted, expected);
    assert_eq!(view.support.products, if recipient == "buyer" { 4 } else { 3 });
    // The inverse and extrema are literal for this one-hop table.
    assert_eq!(view.support.contributors["seller"], self_set("seller"));
    assert_eq!(
        view.support.contributors["buyer"],
        if recipient == "buyer" {
            BTreeSet::from(["seller".into(), "buyer".into()])
        } else {
            self_set("buyer")
        }
    );
    assert_eq!(
        view.support.ranges["buyer"].minimum,
        if recipient == "buyer" { "48" } else { "98" }
    );
    assert_eq!(view.support.ranges["buyer"].maximum, "98");
    assert_eq!(
        view.support.ranges["buyer"].width,
        if recipient == "buyer" { "50" } else { "0" }
    );
}

/// Claim: For verified fixture packages and deterministic formation verification, the joined compiler derives one frozen state from one complete prefix. Independent literal tables cover all nineteen families, ledger counts and debits, cells, coefficients, recipients, sparse base, source emission and support; numeric holds remain explicit and title-dependent recipients follow the released settlement-party rule. The result is neither a solve nor persistent epoch admission.
/// ´claim:compiler:fixed-inputs-determine-the-compiled-state´
/// ´test:integration:compiler-tables´
#[test]
fn compiler_tables() {
    for (family, names, recipient) in FAMILIES {
        let mut acts = family_case(family);
        let result = compile(&acts, 1);
        family_table(family, names, recipient, &result);
        acts.reverse();
        assert_eq!(compile(&acts, 1).view(), result.view());
    }
    special_tables();
    let input = package(&anchors(), 1, &BURNS);
    assert!(matches!(
        compile_final_state(&input, &Verifier, &mut numeric(), Limits::default(), 0),
        Err(CompileError::Support(SupportError::Products))
    ));
    let poor = package(&anchors(), 1, &[("seller", "1"), ("buyer", "100"), ("third", "100")]);
    assert!(
        matches!(compile_final_state(&poor, &Verifier, &mut numeric(), Limits::default(),1000), Err(CompileError::Ledger(pn_epoch::ledger::LedgerError::InsufficientBalance {address, boundary:1})) if address.0 == "seller")
    );
}

fn special_tables() {
    let mut acts = family_case("Invitation");
    let mut opposite = act("Invitation", "seller", 11, 1);
    coordinates(&mut opposite, &["urgency", "formality", "relevance"], -1);
    opposite.body.quantities[4].1.value = 1;
    acts.push(opposite);
    let result = compile(&acts, 1);
    let cell = result
        .view()
        .cells
        .iter()
        .find(|cell| cell.identity.family == "Invitation")
        .unwrap();
    assert_eq!(
        cell.coordinates,
        BTreeMap::from([("urgency".into(), "0".into()), ("formality".into(), "0".into())])
    );
    assert_eq!(
        cell.members,
        BTreeSet::from([id("Invitation", "seller", 10), id("Invitation", "seller", 11)])
    );
    assert_eq!(
        result.view().coefficients[&cell.identity],
        CoefficientEvidence::Exact("0".into())
    );
    base_table(
        &result,
        &[("seller", "seller", "2"), ("buyer", "buyer", "2"), ("third", "third", "2")],
    );
    ledger_table(
        &result,
        &[
            ("seller", 3, "94", "94/3"),
            ("buyer", 1, "98", "98"),
            ("third", 1, "98", "98"),
        ],
    );
    acts.push(act("Invitation", "seller", 12, 2));
    let restored = compile(&acts, 2);
    base_table(
        &restored,
        &[
            ("seller", "seller", "2"),
            ("seller", "buyer", "1"),
            ("buyer", "buyer", "2"),
            ("third", "third", "2"),
        ],
    );
    let cell = restored
        .view()
        .cells
        .iter()
        .find(|cell| cell.identity.family == "Invitation")
        .unwrap();
    assert_eq!(cell.members.len(), 3);
    assert!(cell.coordinates.values().all(|value| value == "1"));
    irrational_and_settlement();
}

fn irrational_and_settlement() {
    let mut irrational = family_case("Opinion");
    irrational[3].body.quantities[1].1.value = 2;
    let held = compile(&irrational, 1);
    let cell = held
        .view()
        .cells
        .iter()
        .find(|cell| cell.identity.family == "Opinion")
        .unwrap();
    assert_eq!(
        held.view().coefficients[&cell.identity],
        CoefficientEvidence::Irrational { radicand: "1/2".into() }
    );
    match &held.view().base.rows["seller"]["buyer"].score {
        BaseScore::Held { exact_part, terms } => {
            assert_eq!(exact_part, "0");
            assert_eq!(terms.len(), 1);
            assert_eq!(terms[0].radicand, "1/2");
            assert_eq!(terms[0].domain_factor, "1");
        }
        BaseScore::Exact(_) => panic!("irrational evidence must remain held"),
    }
    let result = compile(&settlement(), 2);
    ledger_table(
        &result,
        &[
            ("seller", 3, "94", "94/3"),
            ("buyer", 3, "94", "94/3"),
            ("third", 1, "98", "98"),
        ],
    );
    base_table(
        &result,
        &[
            ("seller", "seller", "3"),
            ("seller", "buyer", "1"),
            ("buyer", "buyer", "3"),
            ("buyer", "seller", "1"),
            ("third", "third", "2"),
        ],
    );
    for (family, author, sequence, recipient) in [("Accept", "seller", 6, "buyer"), ("Ratify", "buyer", 7, "seller")] {
        assert_eq!(
            result
                .view()
                .recipients
                .iter()
                .find(|row| row.cell.members.contains(&id(family, author, sequence)))
                .unwrap()
                .recipient,
            recipient
        );
    }
}

/// Claim: The finite compiler portion of the split fixtures preserves the source ledger pair proportionally without copying any act, while separate author cells change the unnormalized base. The witnesses establish compiler inputs to split admissibility and fold export, not equilibrium, conservation, universal split invariance or monotone standing under extra burn.
/// ´claim:compiler:split-witnesses-stop-at-the-compiled-base´
/// ´test:integration:compiler-splits´
#[test]
fn compiler_splits() {
    let coarse = vec![
        act("Registration", "seller", 1, 1),
        act("Registration", "seller", 2, 1),
        act("Registration", "buyer", 3, 1),
        act("Opinion", "seller", 4, 1),
        act("Opinion", "seller", 5, 1),
    ];
    let refined = vec![
        act("Registration", "seller", 1, 1),
        act("Registration", "third", 2, 1),
        act("Registration", "buyer", 3, 1),
        act("Opinion", "seller", 4, 1),
        act("Opinion", "third", 5, 1),
    ];
    let original = compile_final_state(
        &package(&coarse, 1, &[("seller", "200"), ("buyer", "100")]),
        &Verifier,
        &mut numeric(),
        Limits::default(),
        1000,
    )
    .unwrap();
    let split = compile(&refined, 1);
    assert_eq!(original.view().ledger.counts[&Address("seller".into())].0, 4);
    assert_eq!(original.view().ledger.balances[&Address("seller".into())].exact(), "192");
    assert_eq!(original.view().support.sources["seller"].reduced_rate, "48");
    for author in ["seller", "third"] {
        assert_eq!(split.view().ledger.counts[&Address(author.into())].0, 2);
        assert_eq!(split.view().ledger.balances[&Address(author.into())].exact(), "96");
        assert_eq!(split.view().support.sources[author].reduced_rate, "48");
    }
    assert_eq!(original.view().ledger.debits.len(), 5);
    assert_eq!(split.view().ledger.debits.len(), 5);
    base_table(
        &original,
        &[("seller", "seller", "3"), ("seller", "buyer", "1"), ("buyer", "buyer", "2")],
    );
    base_table(
        &split,
        &[
            ("seller", "seller", "2"),
            ("seller", "buyer", "1"),
            ("third", "third", "2"),
            ("third", "buyer", "1"),
            ("buyer", "buyer", "2"),
        ],
    );
    assert_eq!(
        original
            .view()
            .cells
            .iter()
            .find(|cell| cell.identity.family == "Opinion")
            .unwrap()
            .members
            .len(),
        2
    );
    assert_eq!(
        split
            .view()
            .cells
            .iter()
            .filter(|cell| cell.identity.family == "Opinion")
            .count(),
        2
    );
}

fn permutations(acts: &[CandidateAct]) -> Vec<Vec<CandidateAct>> {
    let mut rows = vec![vec![]];
    for act in acts {
        rows = rows
            .into_iter()
            .flat_map(|row| {
                (0..=row.len()).map(move |index| {
                    let mut next = row.clone();
                    next.insert(index, act.clone());
                    next
                })
            })
            .collect();
    }
    rows
}

fn history_key(state: &CompiledState) -> Vec<(pn_records::ActId, pn_records::Position)> {
    state
        .package()
        .input()
        .history
        .acts()
        .iter()
        .map(|act| (act.id().clone(), act.position()))
        .collect()
}

fn place(acts: &mut [CandidateAct]) {
    let mut counts = BTreeMap::new();
    for act in acts {
        let count = counts.entry(act.finalization_epoch).or_insert(0);
        *count += 1;
        act.authoritative_position = *count;
    }
}

// Placement and time evidence must follow the new input, not be erased by the fixture.
// Compare compiler values after checking those two intentionally placement-specific fields.
fn placement_values(state: &CompiledState) -> pn_epoch::compiler::CompiledView {
    let history = &state.package().input().history;
    let mut values = state.view().clone();
    for boundary in &mut values.title.boundaries {
        for candidate in &mut boundary.candidates {
            for (index, id) in candidate.acts.iter().enumerate() {
                let act = history.acts().iter().find(|act| act.id() == id);
                assert_eq!(
                    candidate.chain[index].map(|m| (m.position, m.logical_time)),
                    act.map(|a| (a.position(), a.logical_time()))
                );
                assert_eq!(
                    candidate.times[index].as_ref(),
                    history.time_evidence().iter().find(|row| &row.act == id)
                );
            }
            candidate.chain = [None; 3];
            candidate.times = [None, None, None];
        }
    }
    values
}

fn placement_corpus() {
    let mut mixed = anchors();
    for (sequence, family) in [(4, "Opinion"), (5, "Reference"), (6, "Invitation"), (7, "Tag")] {
        mixed.push(act(family, "seller", sequence, 1));
    }
    let expected = compile(&mixed, 1);
    let mut distinct = BTreeSet::new();
    for tail in permutations(&mixed[3..]) {
        let mut acts = anchors();
        acts.extend(tail);
        place(&mut acts);
        let result = compile(&acts, 1);
        distinct.insert(history_key(&result));
        assert_eq!(placement_values(&result), placement_values(&expected));
    }
    assert_eq!(distinct.len(), 24);
    let mut prefix = anchors();
    prefix.push(act("Owner", "seller", 4, 1));
    let first = joined::handshake("buyer", "seller", 5, 2);
    let second = joined::handshake("third", "seller", 8, 2);
    let mut expected = None;
    let mut distinct = BTreeSet::new();
    // All twenty shuffles of two three-act chains, preserving each Bid < Accept < Ratify.
    for mask in 0_u32..64 {
        if mask.count_ones() != 3 {
            continue;
        }
        let mut acts = prefix.clone();
        let (mut a, mut b) = (first.iter(), second.iter());
        for bit in 0..6 {
            acts.push(if mask & (1 << bit) == 0 { a.next() } else { b.next() }.unwrap().clone());
        }
        place(&mut acts);
        // Candidate admission, independently of replay, establishes compliant parent placement.
        pn_records::validate_history(&acts, &[]).unwrap();
        let result = compile(&acts, 2);
        distinct.insert(history_key(&result));
        let values = placement_values(&result);
        assert_eq!(&values, expected.get_or_insert_with(|| values.clone()));
    }
    assert_eq!(distinct.len(), 20);
}

/// Claim: All 24 accepted-set presentations of each of nineteen family fixtures reach validation unchanged, producing 456 distinct histories and equal joined views. Twenty compliant interleavings of two settlement chains and 24 mixed-family placements preserve compiled values; chain and time evidence are checked against each changed input separately. This is finite compiler determinism, not universal partition invariance.
/// ´claim:compiler:recorded-permutations-preserve-joined-results´
/// ´test:integration:compiler-properties´
#[test]
fn compiler_properties() {
    let mut distinct = BTreeSet::new();
    for (family, _, _) in FAMILIES {
        let acts = family_case(family);
        let expected = compile(&acts, 1);
        for permuted in permutations(&acts) {
            let result = compile(&permuted, 1);
            distinct.insert(history_key(&result));
            assert_eq!(result.view(), expected.view());
        }
    }
    assert_eq!(distinct.len(), 456);
    placement_corpus();
    generated_literal_corpus();
    let acts = aggregate_case("Invitation", 2, 0);
    let expected = compile(&acts, 1);
    let reordered = joined::reordered_package(&acts, 1, &BURNS);
    let result = compile_final_state(&reordered, &Verifier, &mut numeric(), Limits::default(), 1000).unwrap();
    assert_ne!(history_key(&result), history_key(&expected));
    assert_eq!(result.view(), expected.view());
}

fn aggregate_case(family: &str, members: usize, coordinate: usize) -> Vec<CandidateAct> {
    let mut acts = anchors();
    for index in 0..members {
        let mut input = act(family, "seller", 10 + u64::try_from(index).unwrap(), 1);
        for (name, quantity) in &mut input.body.quantities {
            if name.ends_with(".denominator") {
                quantity.value = [4, 2, 1][coordinate];
            }
        }
        acts.push(input);
    }
    place(&mut acts);
    acts
}

fn aggregate_table(family: &str, members: usize, coordinate: usize, state: &CompiledState) {
    let value = [["1/4", "1/2", "1"], ["1/2", "1", "1"], ["3/4", "1", "1"]][members - 1][coordinate];
    let names = match family {
        "Opinion" => ["polarity", "reaction"],
        "Reference" => ["effort", "enthusiasm"],
        "Invitation" => ["urgency", "formality"],
        _ => unreachable!("aggregate fixture family"),
    };
    let view = state.view();
    assert_eq!(view.cells.len(), 4);
    let cell = view.cells.iter().find(|cell| cell.identity.family == family).unwrap();
    assert_eq!(
        cell.members,
        (0..members)
            .map(|i| id(family, "seller", 10 + u64::try_from(i).unwrap()))
            .collect()
    );
    assert_eq!(
        cell.coordinates,
        names.into_iter().map(|name| (name.into(), value.into())).collect()
    );
    assert_eq!(view.coefficients[&cell.identity], CoefficientEvidence::Exact(value.into()));
    assert_eq!(
        view.recipients
            .iter()
            .find(|row| row.cell.identity == cell.identity)
            .unwrap()
            .recipient,
        "buyer"
    );
    let (count, balance, rate) = [(2, "96", "48"), (3, "94", "94/3"), (4, "92", "23")][members - 1];
    ledger_table(
        state,
        &[
            ("seller", count, balance, rate),
            ("buyer", 1, "98", "98"),
            ("third", 1, "98", "98"),
        ],
    );
    base_table(
        state,
        &[
            ("seller", "seller", "2"),
            ("seller", "buyer", value),
            ("buyer", "buyer", "2"),
            ("third", "third", "2"),
        ],
    );
    assert_eq!(
        view.support.emitted["seller"],
        BTreeSet::from(["seller".into(), "buyer".into()])
    );
}

fn generated_literal_corpus() {
    let mut distinct = BTreeSet::new();
    for family in ["Opinion", "Reference", "Invitation"] {
        for members in 1..=3 {
            for coordinate in 0..3 {
                let acts = aggregate_case(family, members, coordinate);
                let result = compile(&acts, 1);
                aggregate_table(family, members, coordinate, &result);
                distinct.insert(format!("{:?}", result.package().input().history.acts()));
            }
        }
    }
    assert_eq!(distinct.len(), 27);
}

use pn_testkit::proptest::{self, prelude::*};

fn configuration() -> proptest::test_runner::Config {
    let mut config = pn_testkit::property_config(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/compiler-regressions.txt"));
    match std::env::var("PN_PROPERTY_SEED_PN_EPOCH") {
        Ok(seed) => config.rng_seed = proptest::test_runner::RngSeed::Fixed(seed.parse().unwrap()),
        Err(std::env::VarError::NotPresent) => assert!(
            std::env::var_os("PN_HARNESS_SOURCE").is_none(),
            "missing consumer seed in gated run"
        ),
        Err(error) => panic!("invalid consumer seed: {error}"),
    }
    config
}

proptest! {
    #![proptest_config(configuration())]
    /// Claim: Source-qualified generated Opinion, Reference and Invitation packages vary one to three members, coordinates from one-quarter through one, published positions and accepted-set presentation. Independent literal tables check the folded coefficient, ledger and base for each case; reversed presentation preserves the joined view. This finite rational alphabet is not arbitrary numeric or deployment history coverage.
    /// ´claim:compiler:generated-packages-match-the-literal-compiler-table´
    /// ´test:integration:compiler-generated´
    #[test]
    fn compiler_generated(family in 0_usize..3, members in 1_usize..4, coordinate in 0_usize..3, words in proptest::collection::vec(any::<u64>(), 1..8)) {
        let family = ["Opinion", "Reference", "Invitation"][family];
        let mut acts = aggregate_case(family, members, coordinate);
        for word in words {
            let len = u64::try_from(acts.len()).unwrap();
            acts.rotate_left(usize::try_from(word % len).unwrap());
            if word & 1 != 0 { acts.reverse(); }
        }
        place(&mut acts);
        let expected = compile(&acts, 1);
        aggregate_table(family, members, coordinate, &expected);
        acts.reverse();
        let result = compile(&acts, 1);
        assert_ne!(history_key(&result), history_key(&expected));
        assert_eq!(result.view(), expected.view());
    }
}
