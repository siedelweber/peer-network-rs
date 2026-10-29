use super::common::{act, named, resolved};
use pn_records::{
    CandidateAct, DependencyProjection, InvalidCause, Layout, ParentCause, PublicReference, Removal, SettlementReferences,
    TimeVerdict, ValidationError, assemble_boundary_inputs, validate_history, validate_record,
};

fn chain() -> [CandidateAct; 3] {
    let mut bid = act(1, Layout::Paired);
    bid.id.family = "Bid".into();
    for leg in &mut bid.legs {
        leg.id.act = bid.id.clone();
        if leg.id.role == pn_records::Role::T {
            leg.target = PublicReference::Minted(bid.id.clone());
        }
    }
    let mut accept = act(2, Layout::Binary);
    accept.id.family = "Accept".into();
    accept.legs[0].id.act = accept.id.clone();
    accept.body.settlement = Some(SettlementReferences::Accept { settles: bid.id.clone() });
    let mut ratify = act(3, Layout::Binary);
    ratify.id.family = "Ratify".into();
    ratify.legs[0].id.act = ratify.id.clone();
    ratify.body.settlement = Some(SettlementReferences::Ratify {
        settles: bid.id.clone(),
        accepts: accept.id.clone(),
    });
    let mut acts = [bid, accept, ratify];
    for (index, act) in acts.iter_mut().enumerate() {
        act.authoritative_position = u64::try_from(index).unwrap() + 1;
        act.logical_time = act.authoritative_position;
    }
    acts
}

fn invalid(act: &CandidateAct) -> ValidationError {
    ValidationError::InvalidRepresentation {
        act: act.id.clone(),
        cause: InvalidCause::SettlementReferences,
    }
}

/// Claim: Typed settlement metadata contributes distinct Bid and Accept parents to principal closures without a repeated asserted declaration; explicit repetition, input order and payload removal preserve the same parent set and closure work, while fixed history stays outside membership.
/// ´claim:acts:settlement-references-join-distinct-causal-parents´
/// ´test:integration:settlement-closures´
#[test]
fn settlement_closures() {
    let original = chain();
    let mut expected_work = None;
    for repeated in [false, true] {
        for removed in [false, true] {
            for reversed in [false, true] {
                let mut acts = original.clone();
                for act in &mut acts {
                    if repeated {
                        act.body.asserted_parents = act.body.causal_parents().into_iter().cloned().collect();
                    }
                    if removed {
                        act.projections.content = Removal::Tombstoned((6, 1));
                        act.projections.dependency = DependencyProjection::Tombstoned((6, 1));
                    }
                }
                if reversed {
                    acts.reverse();
                }
                let records = validate_record(&acts, &resolved(), &[]).unwrap();
                let inputs = assemble_boundary_inputs(&records, (5, 1)).unwrap();
                for (closure, count) in inputs.closures().iter().zip(1..=3) {
                    assert_eq!(
                        closure.members(),
                        &original[..count].iter().map(|act| act.id.clone()).collect::<Vec<_>>()
                    );
                }
                assert_eq!(*expected_work.get_or_insert(inputs.work()), inputs.work());
            }
        }
    }
    for cut in 1..=2 {
        let history = validate_history(&original[..cut], &[named("left"), named("right")]).unwrap();
        let records = validate_record(&original[cut..], &history, &[]).unwrap();
        let inputs = assemble_boundary_inputs(&records, (5, u64::try_from(cut).unwrap() + 1)).unwrap();
        assert_eq!(
            inputs.closures().last().unwrap().members(),
            &original[cut..].iter().map(|act| act.id.clone()).collect::<Vec<_>>()
        );
    }
}

/// Claim: Settlement metadata is required only in its matching Accept or Ratify variant, requires existing earlier act targets, and retains wrong-family or different-Bid references without a binding verdict. Missing targets, malformed variants and non-earlier placement still refuse; family and same-Bid binding belong to recognition.
/// ´claim:acts:settlement-targets-require-existing-earlier-acts´
/// ´test:integration:settlement-targets´
#[test]
fn settlement_targets() {
    let original = chain();
    for index in [1, 2] {
        let mut acts = original.clone();
        acts[index].body.settlement = None;
        assert_eq!(validate_record(&acts, &resolved(), &[]).unwrap_err(), invalid(&acts[index]));
        let mut acts = original.clone();
        acts[index].body.settlement = original[3 - index].body.settlement.clone();
        assert_eq!(validate_record(&acts, &resolved(), &[]).unwrap_err(), invalid(&acts[index]));
    }
    for family in [
        "Registration",
        "Affinity",
        "Publish",
        "Owner",
        "Participant",
        "Review",
        "Send",
        "Bid",
        "Opinion",
        "Join Request",
        "Tag",
        "Leave",
        "Reference",
        "Invitation",
        "De-invite",
        "Withdraw",
        "Rescind",
    ] {
        let mut extra = act(10, Layout::Binary);
        extra.id.family = family.into();
        extra.legs[0].id.act = extra.id.clone();
        extra.body.settlement = original[1].body.settlement.clone();
        assert_eq!(
            validate_record(std::slice::from_ref(&extra), &resolved(), &[]).unwrap_err(),
            invalid(&extra)
        );
    }
    for missing in [0, 1] {
        let mut acts = original.to_vec();
        let id = acts.remove(missing).id;
        assert_eq!(
            validate_record(&acts, &resolved(), &[]).unwrap_err(),
            ValidationError::UnresolvedReference(PublicReference::Act(id))
        );
    }
    let mut acts = original.clone();
    acts[0].legs[1].target = named("right");
    assert!(validate_record(&acts, &resolved(), &[]).is_ok());
    let mut acts = original.clone();
    acts[0].id.family = "Other".into();
    for leg in &mut acts[0].legs {
        leg.id.act.family = "Other".into();
    }
    acts[0].legs[1].target = named("right");
    acts[1].body.settlement = Some(SettlementReferences::Accept {
        settles: acts[0].id.clone(),
    });
    acts[2].body.settlement = Some(SettlementReferences::Ratify {
        settles: acts[0].id.clone(),
        accepts: acts[1].id.clone(),
    });
    assert!(validate_record(&acts, &resolved(), &[]).is_ok());
    acts[2].body.settlement = Some(SettlementReferences::Ratify {
        settles: acts[0].id.clone(),
        accepts: acts[0].id.clone(),
    });
    assert!(validate_record(&acts, &resolved(), &[]).is_ok());
    let mut acts = original.to_vec();
    let mut other = acts[0].clone();
    other.id.sequence = 4;
    other.authoritative_position = 0;
    other.logical_time = 0;
    for leg in &mut other.legs {
        leg.id.act = other.id.clone();
    }
    other.legs[1].target = PublicReference::Minted(other.id.clone());
    acts[2].body.settlement = Some(SettlementReferences::Ratify {
        settles: other.id.clone(),
        accepts: acts[1].id.clone(),
    });
    acts.push(other);
    assert!(validate_record(&acts, &resolved(), &[]).is_ok());
}

/// Claim: Candidate admission orders settlement parents before their children within a batch and across epoch-qualified history cuts, without requiring an additional asserted-parent declaration; reversed Bid/Accept and Accept/Ratify placement refuses.
/// ´claim:acts:settlement-parents-obey-candidate-order´
/// ´test:integration:settlement-order´
#[test]
fn settlement_order() {
    for cross_epoch in [false, true] {
        let mut original = chain();
        if cross_epoch {
            for (index, act) in original.iter_mut().enumerate() {
                act.finalization_epoch = u64::try_from(index).unwrap() + 1;
                act.authoritative_position = 1;
            }
        }
        for cut in 0..=2 {
            let history = validate_history(&original[..cut], &[named("left"), named("right")]).unwrap();
            validate_record(&original[cut..], &history, &[]).unwrap();
        }
        for child in [1, 2] {
            let mut acts = original.clone();
            let parent = child - 1;
            acts[child].finalization_epoch = acts[parent].finalization_epoch;
            acts[child].authoritative_position = acts[parent].authoritative_position;
            assert_eq!(
                validate_record(&acts, &resolved(), &[]).unwrap_err(),
                ValidationError::Parent {
                    act: acts[child].id.clone(),
                    parent: Some(acts[parent].id.clone()),
                    cause: ParentCause::NotEarlier,
                }
            );
        }
    }
}

/// Claim: Time recomputation reads settlement parents even on disjoint endpoints, retains a mismatching published stamp unchanged, and reads the same parent relation after explicit repetition without rewriting the published stamp.
/// ´claim:acts:settlement-parents-enter-retained-time-checks´
/// ´test:integration:settlement-time´
#[test]
fn settlement_time() {
    let mut acts = chain();
    acts[0].logical_time = 1;
    acts[1].logical_time = 2;
    acts[2].logical_time = 3;
    let mut names = vec![named("left"), named("right")];
    for act in &mut acts[1..] {
        let endpoint = named(&act.id.family);
        names.push(endpoint.clone());
        act.legs[0].source = endpoint.clone();
        act.legs[0].target = endpoint;
    }
    for repeated in [false, true] {
        if repeated {
            for act in &mut acts {
                act.body.asserted_parents = act.body.causal_parents().into_iter().cloned().collect();
            }
        }
        let history = validate_history(&acts, &names).unwrap();
        assert_eq!(history.time_evidence()[1].verdict, TimeVerdict::Matches);
        assert_eq!(history.time_evidence()[2].verdict, TimeVerdict::Matches);
    }
    acts[1].logical_time = 7;
    let history = validate_history(&acts, &names).unwrap();
    assert_eq!(
        history.time_evidence()[1].verdict,
        TimeVerdict::Mismatch {
            attached: 7,
            expected: 2
        }
    );
    assert_eq!(history.acts()[1].logical_time(), 7);
}
