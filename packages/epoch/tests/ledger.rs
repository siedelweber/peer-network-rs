mod common;

use pn_epoch::{
    CompilerInputs, bind_inputs,
    ledger::{LedgerError, compile_ledger},
};
use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::burn::{AcceptedSet, Address};
use pn_records::constants::bind_constants;
use pn_records::numerics::{ChargedPrice, ComparisonLimits, ExactLimits, NumericContext};
use pn_records::test_support::burn;
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, StructuralBody, ValidatedAct, validate_history, validate_record,
};

#[derive(Debug)]
struct Verifier;
impl RegistrationVerifier for Verifier {
    fn approval(&self, act: &ValidatedAct) -> bool {
        act.authentication_evidence() == [1]
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        true
    }
}

fn context() -> NumericContext {
    NumericContext::new(ExactLimits::default(), ComparisonLimits::new(1000, 1000)).unwrap()
}

fn parameters(c: &mut NumericContext) -> (Vec<CompilerInputs>, Vec<ChargedPrice>) {
    let (declaration, edition, first) = common::fixture();
    let empty = validate_history(&[], &[]).unwrap();
    let records = validate_record(&[], &empty, &[declaration]).unwrap();
    let history = bind_constants(&records, vec![edition]).unwrap();
    let mut second = first.clone();
    second.boundary = 2;
    let inputs = [first, second]
        .into_iter()
        .map(|input| bind_inputs(&history, input, ExactLimits::default()).unwrap())
        .collect::<Vec<_>>();
    let prices = inputs
        .iter()
        .zip(["1", "2"])
        .map(|(input, value)| {
            let value = c.literal(value).unwrap();
            let wall = c.computed(&value).unwrap();
            c.charged_price(&wall, &input.parameters().numeraire, input.constants().content().floor)
                .unwrap()
        })
        .collect();
    (inputs, prices)
}

fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}

fn acts() -> Vec<CandidateAct> {
    let id = ActId {
        author: "address-2".into(),
        sequence: 1,
        family: "Registration".into(),
    };
    let first = CandidateAct {
        commitments: None,
        id: id.clone(),
        body: StructuralBody {
            settlement: None,
            license: None,
            asserted_parents: vec![],
            layout: Layout::Binary,
            quantities: vec![],
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: named("addr", "address-2"),
            target: named("prof", "address-2"),
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: 1,
        logical_time: 1,
    };
    let mut second = first.clone();
    second.id = ActId {
        author: "address-2".into(),
        sequence: 2,
        family: "Send".into(),
    };
    second.finalization_epoch = 2;
    second.logical_time = 2;
    second.body.layout = Layout::Paired;
    second.body.quantities = [("importance.numerator", -1), ("importance.denominator", 2)]
        .into_iter()
        .map(|(name, value)| {
            (
                name.into(),
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect();
    let middle = PublicReference::Minted(ActId {
        author: "address-2".into(),
        sequence: 99,
        family: "Participant".into(),
    });
    second.legs = vec![
        CandidateLeg {
            id: EdgeId {
                act: second.id.clone(),
                role: Role::A,
            },
            source: named("addr", "address-2"),
            target: middle.clone(),
            removal: None,
        },
        CandidateLeg {
            id: EdgeId {
                act: second.id.clone(),
                role: Role::T,
            },
            source: middle,
            target: PublicReference::Minted(second.id.clone()),
            removal: None,
        },
    ];
    vec![first, second]
}

fn solvency_boundaries() {
    let mut c = context();
    let (inputs, prices) = parameters(&mut c);
    let markers = burn::recognize(burn::generate(&[9])).unwrap();
    let accepted = acts();
    let history = validate_history(&accepted, &[]).unwrap();
    let address = Address("address-2".into());
    let first_history = validate_history(&accepted[..1], &[]).unwrap();
    let literal = c.literal("10").unwrap();
    let wall = c.computed(&literal).unwrap();
    let exact_balance = c
        .charged_price(
            &wall,
            &inputs[0].parameters().numeraire,
            inputs[0].constants().content().floor,
        )
        .unwrap();
    let exhausted = compile_ledger(
        &inputs[..1],
        &[exact_balance],
        &markers,
        &first_history,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    assert_eq!(exhausted.balances[&address].exact(), "0");
    let literal = c.literal("11").unwrap();
    let wall = c.computed(&literal).unwrap();
    let excessive = c
        .charged_price(
            &wall,
            &inputs[0].parameters().numeraire,
            inputs[0].constants().content().floor,
        )
        .unwrap();
    assert_eq!(
        compile_ledger(
            &inputs,
            &[excessive, prices[1].clone()],
            &markers,
            &history,
            &Verifier,
            &mut c,
            ExactLimits::default()
        ),
        Err(LedgerError::InsufficientBalance { address, boundary: 1 })
    );
}

fn registration_for(author: &str, sequence: u64, position: u64) -> CandidateAct {
    let mut act = acts().remove(0);
    act.id.author = author.into();
    act.id.sequence = sequence;
    act.legs[0].id.act = act.id.clone();
    act.legs[0].source = named("addr", author);
    act.legs[0].target = named("prof", author);
    act.authoritative_position = position;
    act
}

fn fractional_own_balances() {
    let mut c = context();
    let (inputs, _) = parameters(&mut c);
    let literal = c.literal("3/2").unwrap();
    let wall = c.computed(&literal).unwrap();
    let price = c
        .charged_price(
            &wall,
            &inputs[0].parameters().numeraire,
            inputs[0].constants().content().floor,
        )
        .unwrap();
    let mut raw = burn::generate(&[9]);
    raw.burn.read_addresses.insert(Address("address-3".into()));
    for (address, amount) in [("address-2", "5/2"), ("address-3", "9/2")] {
        let literal = c.literal(amount).unwrap();
        raw.burn
            .amounts
            .insert(Address(address.into()), c.burn(&literal, "burn").unwrap());
    }
    for record in &mut raw.history.records {
        record.address = Address(if record.identity == "r1" { "address-3" } else { "address-2" }.into());
        record.amount = raw.burn.amounts[&record.address].clone();
        record.evidence = format!(
            "{}:{}:{}:{}",
            record.destruction,
            record.address.0,
            record.amount.exact(),
            record.amount.unit()
        )
        .into_bytes();
    }
    raw.history.markers[1].accepted = AcceptedSet::CompleteList(["r0".into(), "r1".into()].into_iter().collect());
    let markers = burn::recognize(raw).unwrap();
    let first = registration_for("address-2", 1, 1);
    let second = registration_for("address-3", 1, 2);
    let a = Address("address-2".into());
    let b = Address("address-3".into());
    let history = validate_history(&[first.clone(), second.clone()], &[]).unwrap();
    let result = compile_ledger(
        &inputs[..1],
        std::slice::from_ref(&price),
        &markers,
        &history,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    assert_eq!(result.balances[&a].exact(), "1");
    assert_eq!(result.balances[&b].exact(), "3");
    assert_eq!(result.debits[&first.id].charged().exact(), "3/2");
    assert_eq!(result.debits[&second.id].charged().exact(), "3/2");
    for (author, address, balance) in [("address-2", &a, "1"), ("address-3", &b, "3")] {
        let alone = validate_history(&[registration_for(author, 1, 1)], &[]).unwrap();
        let alone = compile_ledger(
            &inputs[..1],
            std::slice::from_ref(&price),
            &markers,
            &alone,
            &Verifier,
            &mut c,
            ExactLimits::default(),
        )
        .unwrap();
        assert_eq!(alone.balances[address].exact(), balance);
        assert_eq!(alone.balances[address], result.balances[address]);
    }
    let more_solvent = validate_history(&[first.clone(), second.clone(), registration_for("address-3", 2, 3)], &[]).unwrap();
    let result = compile_ledger(
        &inputs[..1],
        std::slice::from_ref(&price),
        &markers,
        &more_solvent,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    assert_eq!(result.balances[&a].exact(), "1");
    assert_eq!(result.balances[&b].exact(), "3/2");
    let insolvent = validate_history(&[first, second, registration_for("address-2", 2, 3)], &[]).unwrap();
    assert_eq!(
        compile_ledger(
            &inputs[..1],
            &[price],
            &markers,
            &insolvent,
            &Verifier,
            &mut c,
            ExactLimits::default()
        ),
        Err(LedgerError::InsufficientBalance { address: a, boundary: 1 })
    );
}

/// Claim: Replaying one recognized marker prefix derives exact cumulative and first-accepted burn by destruction identity, including aliases, delayed acceptance and empty-act epochs; final balances subtract each complete act's writing-price debit once, retain prior vintages and refuse own-balance insolvency without returning a partial ledger.
/// ´claim:compiler:recognized-prefix-derives-the-final-ledger´
/// ´test:integration:ledger-derivation´
#[test]
fn ledger_derivation() {
    let mut c = context();
    let (inputs, prices) = parameters(&mut c);
    let raw = burn::generate(&[9]);
    let markers = burn::recognize(raw.clone()).unwrap();
    let empty = validate_history(&[], &[]).unwrap();
    let result = compile_ledger(&inputs, &prices, &markers, &empty, &Verifier, &mut c, ExactLimits::default()).unwrap();
    let address = Address("address-2".into());
    assert_eq!(result.snapshots[0].gross[&address].exact(), "10");
    assert_eq!(result.snapshots[1].gross[&address].exact(), "20");
    assert_eq!(result.snapshots[1].increment[&address].exact(), "10");
    assert_eq!(result.balances[&address].exact(), "20");
    assert_eq!(result.counts[&address].0, 0);
    assert!(result.debits.is_empty());
    let mut alias_only = raw.clone();
    alias_only.history.markers[2].accepted = AcceptedSet::CompleteList(["r0".into(), "alias".into()].into_iter().collect());
    let aliases = burn::recognize(alias_only).unwrap();
    let result = compile_ledger(&inputs, &prices, &aliases, &empty, &Verifier, &mut c, ExactLimits::default()).unwrap();
    assert!(result.snapshots[1].increment.is_empty());
    assert_eq!(result.balances[&address].exact(), "10");
    let accepted = acts();
    let history = validate_history(&accepted, &[]).unwrap();
    let result = compile_ledger(
        &inputs,
        &prices,
        &markers,
        &history,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    assert_eq!(result.balances[&address].exact(), "17");
    assert_eq!(result.counts[&address].0, 2);
    let mut reversed = accepted.clone();
    reversed.reverse();
    let reversed = validate_history(&reversed, &[]).unwrap();
    assert_eq!(
        compile_ledger(
            &inputs,
            &prices,
            &markers,
            &reversed,
            &Verifier,
            &mut c,
            ExactLimits::default()
        )
        .unwrap(),
        result
    );
    solvency_boundaries();
    fractional_own_balances();
    assert_eq!(
        compile_ledger(
            &inputs[1..],
            &prices[1..],
            &markers,
            &empty,
            &Verifier,
            &mut c,
            ExactLimits::default()
        ),
        Err(LedgerError::Boundary)
    );
    let mut unapproved = accepted;
    unapproved[0].authentication_evidence = vec![2];
    let unapproved = validate_history(&unapproved, &[]).unwrap();
    assert_eq!(
        compile_ledger(
            &inputs,
            &prices,
            &markers,
            &unapproved,
            &Verifier,
            &mut c,
            ExactLimits::default()
        ),
        Err(LedgerError::Formation(pn_graph::registration::RegistrationError::Unapproved))
    );
}

/// Claim: Registration and a complete paired Send give two identities, three projections, two debits and two counts.
/// (´[RECORDS-claim:acts:complete-acts-are-counted-once]´)
/// (´claim:compiler:recognized-prefix-derives-the-final-ledger´)
/// ´test:integration:whole-act-ledger´
#[test]
fn whole_act_ledger() {
    let mut c = context();
    let (inputs, prices) = parameters(&mut c);
    let markers = burn::recognize(burn::generate(&[9])).unwrap();
    let history = validate_history(&acts(), &[]).unwrap();
    let graph = pn_graph::formation::reconstruct_replay(&history, &Verifier).unwrap();
    assert_eq!(graph.edge_count(), 3);
    let ledger = compile_ledger(
        &inputs,
        &prices,
        &markers,
        &history,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    assert_eq!(ledger.debits.len(), 2);
    assert_eq!(ledger.counts[&Address("address-2".into())].0, 2);
}

/// Claim: A later epoch charges its new price while the earlier act retains its original exact debit.
/// (´[RECORDS-claim:ledger:later-prices-preserve-charged-vintages]´)
/// (´claim:compiler:recognized-prefix-derives-the-final-ledger´)
/// ´test:integration:ledger-vintages´
#[test]
fn ledger_vintages() {
    let mut c = context();
    let (inputs, prices) = parameters(&mut c);
    let markers = burn::recognize(burn::generate(&[9])).unwrap();
    let accepted = acts();
    let first = validate_history(&accepted[..1], &[]).unwrap();
    let old = compile_ledger(
        &inputs[..1],
        &prices[..1],
        &markers,
        &first,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    let history = validate_history(&accepted, &[]).unwrap();
    let new = compile_ledger(
        &inputs,
        &prices,
        &markers,
        &history,
        &Verifier,
        &mut c,
        ExactLimits::default(),
    )
    .unwrap();
    assert_eq!(old.debits[&accepted[0].id], new.debits[&accepted[0].id]);
    assert_eq!(new.debits[&accepted[0].id].charged().exact(), "1");
    assert_eq!(new.debits[&accepted[1].id].charged().exact(), "2");
}

/// Claim: Repeated public aliases of one destruction leave its cumulative amount and first-accepted boundary unchanged.
/// (´[RECORDS-claim:burn:destruction-aliases-retain-one-contribution-identity]´)
/// (´claim:compiler:recognized-prefix-derives-the-final-ledger´)
/// ´test:integration:ledger-aliases´
#[test]
fn ledger_aliases() {
    let mut c = context();
    let (inputs, prices) = parameters(&mut c);
    let raw = burn::generate(&[9]);
    let original = burn::recognize(raw.clone()).unwrap();
    let mut without_alias = raw;
    without_alias.history.markers[2].accepted = AcceptedSet::CompleteList(["r0".into(), "r1".into()].into_iter().collect());
    let other = burn::recognize(without_alias).unwrap();
    let empty = validate_history(&[], &[]).unwrap();
    let a = compile_ledger(&inputs, &prices, &original, &empty, &Verifier, &mut c, ExactLimits::default()).unwrap();
    let b = compile_ledger(&inputs, &prices, &other, &empty, &Verifier, &mut c, ExactLimits::default()).unwrap();
    assert_eq!(a, b);
}
