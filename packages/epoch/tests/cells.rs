mod common;

use nrz_cas::limits::Limits;
use pn_epoch::cells::{CellError, fold_cells};
use pn_graph::registration::{OpeningKind, RegistrationVerifier};
use pn_records::{
    ActId, CandidateAct, CandidateLeg, DependencyProjection, EdgeId, Layout, Position, PublicReference, Quantity,
    RemovableProjections, Removal, Role, StructuralBody, ValidatedAct, validate_history,
};

#[derive(Debug)]
struct Verifier;
impl RegistrationVerifier for Verifier {
    fn approval(&self, _: &ValidatedAct) -> bool {
        true
    }
    fn removal(&self, _: &ValidatedAct, _: OpeningKind, _: Position) -> bool {
        true
    }
}

fn named(namespace: &str, name: &str) -> PublicReference {
    PublicReference::Named {
        namespace: namespace.into(),
        name: name.into(),
    }
}

fn act(position: u64, family: &str, values: &[(&str, i64, i64)]) -> CandidateAct {
    let id = ActId {
        author: "address-2".into(),
        sequence: position,
        family: family.into(),
    };
    let quantities = values
        .iter()
        .flat_map(|(name, numerator, denominator)| {
            [
                (format!("{name}.numerator"), *numerator),
                (format!("{name}.denominator"), *denominator),
            ]
        })
        .map(|(name, value)| {
            (
                name,
                Quantity {
                    value,
                    unit: "one".into(),
                    vintage: 0,
                },
            )
        })
        .collect();
    CandidateAct {
        commitments: None,
        id: id.clone(),
        body: StructuralBody {
            settlement: None,
            license: None,
            asserted_parents: vec![],
            layout: Layout::Binary,
            quantities,
        },
        legs: vec![CandidateLeg {
            id: EdgeId {
                act: id,
                role: Role::Binary,
            },
            source: named("addr", "address-2"),
            target: named("prof", "target"),
            removal: None,
        }],
        projections: RemovableProjections {
            content: Removal::Live,
            dependency: DependencyProjection::FullEmpty,
        },
        protocol_references: vec![],
        authentication_evidence: vec![1],
        finalization_epoch: 1,
        authoritative_position: position,
        logical_time: position,
    }
}

fn opinion(position: u64, numerator: i64) -> CandidateAct {
    act(position, "Opinion", &[("polarity", numerator, 4), ("reaction", 1, 2)])
}

fn charged_members(acts: &[CandidateAct]) {
    use pn_records::{
        constants::bind_constants,
        numerics::{ComparisonLimits, NumericContext},
        test_support::burn,
        validate_record,
    };
    let (declaration, edition, input) = common::fixture();
    let empty = validate_history(&[], &[]).unwrap();
    let records = validate_record(&[], &empty, &[declaration]).unwrap();
    let constants = bind_constants(&records, vec![edition]).unwrap();
    let inputs = pn_epoch::bind_inputs(&constants, input, Limits::default()).unwrap();
    let mut numeric = NumericContext::new(Limits::default(), ComparisonLimits::new(1000, 1000)).unwrap();
    let one = numeric.literal("1").unwrap();
    let wall = numeric.computed(&one).unwrap();
    let price = numeric
        .charged_price(&wall, &inputs.parameters().numeraire, inputs.constants().content().floor)
        .unwrap();
    let markers = burn::recognize(burn::generate(&[9])).unwrap();
    let history = validate_history(acts, &[]).unwrap();
    let ledger = pn_epoch::ledger::compile_ledger(
        &[inputs],
        &[price],
        &markers,
        &history,
        &Verifier,
        &mut numeric,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(ledger.debits.len(), acts.len());
    assert_eq!(
        ledger.counts[&pn_records::burn::Address("address-2".into())].0,
        u64::try_from(acts.len()).unwrap()
    );
    assert!(ledger.debits.values().all(|debit| debit.charged().exact() == "1"));
}

/// Claim: Complete Opinion bundles retain all member identities while exact rational coordinates sum before clipping; literal tables distinguish sequential clipping, exact cancellation and parallel identities, and each member retains its ledger count and debit.
/// ´claim:compiler:cells-retain-members-and-sum-before-clipping´
/// ´test:integration:cell-tables´
#[test]
fn cell_tables() {
    for (numerators, polarity, reaction) in [
        (vec![3, 3, -3], "3/4", "1"),
        (vec![3, -3], "0", "1"),
        (vec![-4, -4], "-1", "1"),
        (vec![1, 1], "1/2", "1"),
    ] {
        let acts: Vec<_> = numerators
            .into_iter()
            .enumerate()
            .map(|(i, n)| opinion(u64::try_from(i).unwrap() + 1, n))
            .collect();
        let history = validate_history(&acts, &[]).unwrap();
        let result = fold_cells(&history, 1, &Verifier, Limits::default()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].members, acts.iter().map(|act| act.id.clone()).collect());
        assert_eq!(result[0].coordinates["polarity"], polarity);
        assert_eq!(result[0].coordinates["reaction"], reaction);
        let reverse: Vec<_> = acts.iter().rev().cloned().collect();
        assert_eq!(
            result,
            fold_cells(&validate_history(&reverse, &[]).unwrap(), 1, &Verifier, Limits::default()).unwrap()
        );
        charged_members(&acts);
    }
}

fn reference(position: u64, middle: &str) -> CandidateAct {
    let mut result = act(position, "Reference", &[("effort", 1, 2), ("enthusiasm", 1, 2)]);
    result.body.layout = Layout::Paired;
    result.legs[0].id.role = Role::A;
    result.legs[0].target = named("name", middle);
    result.legs.push(CandidateLeg {
        id: EdgeId {
            act: result.id.clone(),
            role: Role::T,
        },
        source: named("name", middle),
        target: named("prof", "target"),
        removal: None,
    });
    result
}

/// Claim: Cell equivalence includes author, family and every role's source and target; complete paired Reference acts stay atomic, distinct middle incidence does not merge, and home-only Affinity acts remain singletons.
/// ´claim:compiler:cells-key-full-incidence-and-excluded-identities´
/// ´test:integration:cell-incidence´
#[test]
fn cell_incidence() {
    let acts = vec![reference(1, "first"), reference(2, "first"), reference(3, "second")];
    let result = fold_cells(&validate_history(&acts, &[]).unwrap(), 1, &Verifier, Limits::default()).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result.iter().map(|cell| cell.members.len()).sum::<usize>(), 3);
    assert!(result.iter().all(|cell| cell.identity.incidence.len() == 2));
    let mut others = vec![opinion(1, 1), opinion(2, 1), opinion(3, 1)];
    others[1].id.author = "other".into();
    others[1].legs[0].id.act = others[1].id.clone();
    others[1].legs[0].source = named("addr", "other");
    others[2].legs[0].target = named("prof", "different");
    assert_eq!(
        fold_cells(&validate_history(&others, &[]).unwrap(), 1, &Verifier, Limits::default())
            .unwrap()
            .len(),
        3
    );
    let mut excluded: Vec<_> = (1..=2)
        .map(|i| act(i, "Affinity", &[("association", 1, 2), ("attraction", 1, 2)]))
        .collect();
    for act in &mut excluded {
        act.legs[0].target = named("name", "target");
    }
    let cells = fold_cells(&validate_history(&excluded, &[]).unwrap(), 1, &Verifier, Limits::default()).unwrap();
    assert_eq!(cells.len(), 2);
    assert!(
        cells
            .iter()
            .all(|cell| cell.members.len() == 1 && cell.coordinates["association"] == "1/2")
    );
}

/// Claim: A formed Invitation causes the entire cell result to hold for its withdrawal edition, without suppressing or discarding an accepted act.
/// ´claim:compiler:invitation-cells-await-withdrawal-edition´
/// ´test:integration:invitation-hold´
#[test]
fn invitation_hold() {
    let mut invitation = act(
        2,
        "Invitation",
        &[("urgency", 1, 2), ("formality", 1, 2), ("relevance", 1, 2)],
    );
    invitation.body.layout = Layout::Paired;
    let middle = PublicReference::Minted(ActId {
        author: "address-2".into(),
        sequence: 99,
        family: "Participant".into(),
    });
    invitation.legs[0].id.role = Role::A;
    invitation.legs[0].target = middle.clone();
    invitation.legs.push(CandidateLeg {
        id: EdgeId {
            act: invitation.id.clone(),
            role: Role::T,
        },
        source: middle,
        target: named("prof", "target"),
        removal: None,
    });
    let history = validate_history(&[opinion(1, 1), invitation], &[]).unwrap();
    assert_eq!(
        fold_cells(&history, 1, &Verifier, Limits::default()),
        Err(CellError::InvitationEdition)
    );
    assert_eq!(history.acts().len(), 2);
    assert_eq!(
        fold_cells(&history, 0, &Verifier, Limits::default()),
        Err(CellError::Boundary)
    );
}
