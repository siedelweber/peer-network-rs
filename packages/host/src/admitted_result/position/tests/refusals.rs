use super::*;

fn invalid(result: Result<(), Error>, case: &str) {
    assert_eq!(result, Err(Error::InvalidPosition), "private position refusal: {case}");
}

/// Claim: Malformed untrusted carriers reach the position reader's private input checks without forging an admitted package; empty frames, empty recognition, missing boundary and inconsistent genesis refuse.
/// ´claim:history:position-private-input´
/// ´test:unit:position-private-input´
#[test]
fn position_private_input() {
    let original = packages().0.carrier();
    for case in ["frames", "recognition", "boundary", "genesis-content", "genesis-point"] {
        let mut carrier = original.clone();
        match case {
            "frames" => carrier.frames.clear(),
            "recognition" => {
                carrier.frames[0].marker_history.markers.clear();
                recognize(&mut carrier.frames[0]);
                assert_eq!(carrier.frames[0].closure.markers.markers(), []);
            }
            "boundary" => carrier.frames[0].parameters.boundary = 999,
            "genesis-content" | "genesis-point" => {
                let genesis = carrier
                    .causes
                    .declarations
                    .iter_mut()
                    .find(|d| d.id.namespace == "deployment")
                    .unwrap();
                genesis.content = if case == "genesis-content" {
                    DeclarationContent::Opaque
                } else {
                    DeclarationContent::Deployment { genesis_at: 999 }
                };
            }
            _ => unreachable!(),
        }
        invalid(Input::carrier(&carrier).map(|_| ()), case);
    }
    assert!(Input::carrier(original).is_ok());
}

/// Claim: Public `from_package` refuses an admitted child paired with a position from another admitted genesis declaration. The other caller-parent pairings are witnessed privately, alongside initial name or history, absent disclosed parent, missing or duplicate records and child-context refusals; scope-changing components are not transition admission witnesses.
/// ´claim:history:position-private-parent´
/// ´test:unit:position-private-parent´
#[test]
fn position_private_parent() {
    public_parent_pairing();
    let root = Input::admitted(&packages().0).unwrap();
    let child = Input::admitted(&packages().1).unwrap();
    for case in ["initial-name", "initial-history", "duplicate-record", "missing-record"] {
        let mut frame = root.frame.clone();
        match case {
            "initial-name" => frame.marker_policy.initial_marker.push_str("-changed"),
            "initial-history" => frame.marker_history.identity.push_str("-changed"),
            "duplicate-record" => frame.marker_history.records.push(frame.marker_history.records[0].clone()),
            "missing-record" => frame.marker_history.records.clear(),
            _ => unreachable!(),
        }
        invalid(input(&frame, root.genesis).validate(None), case);
    }
    let mut genesis = child.genesis.clone();
    genesis.id.edition += 1;
    invalid(input(child.frame, &genesis).validate(Some(&root)), "child-genesis");
    let mut frame = child.frame.clone();
    frame.marker_policy.cadence.push_str("-changed");
    invalid(input(&frame, child.genesis).validate(Some(&root)), "child-policy");
    let initial_frame = vector_frame("initial-lineage", root.frame.clone());
    let mut changed = input(child.frame, child.genesis);
    changed.initial = &initial_frame.closure.markers.markers()[0];
    invalid(changed.validate(Some(&root)), "child-initial-marker");
    ancestry_refusals(&root, &child);
}

fn public_parent_pairing() {
    let (child, verifier) = fixture::complete();
    let mut disclosure = child.disclosures();
    disclosure.frames.truncate(1);
    disclosure
        .causes
        .declarations
        .iter_mut()
        .find(|d| d.id.namespace == "deployment")
        .unwrap()
        .id
        .edition += 1;
    let other = d::restore(disclosure, &verifier).unwrap();
    let parent = position(&other, None);
    assert_eq!(
        Position::from_package(
            &child,
            Some(&parent),
            RECIPE,
            usize::MAX,
            &mut EncodingUsage::default(),
            |_| Ok(())
        )
        .map(|_| ()),
        Err(Error::InvalidPosition),
        "public parent pairing refuses child-genesis mismatch"
    );
}

fn ancestry_refusals(root: &Input<'_>, child: &Input<'_>) {
    let mut initial_only = root.frame.clone();
    initial_only.marker_history.markers.truncate(1);
    recognize(&mut initial_only);
    let mut absent = child.frame.clone();
    absent.closure.markers = initial_only.closure.markers;
    let changed = Input {
        frame: &absent,
        genesis: child.genesis,
        initial: child.initial,
        terminal: child.terminal,
    };
    invalid(changed.validate(Some(root)), "disclosed-parent-absent");
    let mut parent_frame = root.frame.clone();
    parent_frame.marker_history.markers[1].history_position += 10;
    recognize(&mut parent_frame);
    let parent = input(&parent_frame, root.genesis);
    let mut child_frame = child.frame.clone();
    child_frame.marker_history.markers[1].history_position += 10;
    child_frame.marker_history.markers[2].history_position += 20;
    child_frame.marker_history.markers[2].predecessor = Some(parent.terminal.identity().history_position);
    recognize(&mut child_frame);
    // Only the disclosed parent differs; the candidate's predecessor matches the supplied parent.
    let candidate = input(&child_frame, child.genesis);
    let mut disclosed = child_frame.clone();
    disclosed.closure.markers = child.frame.closure.markers.clone();
    let changed = Input {
        frame: &disclosed,
        genesis: child.genesis,
        initial: candidate.initial,
        terminal: candidate.terminal,
    };
    invalid(changed.validate(Some(&parent)), "disclosed-parent");
    for case in ["child-history-scope", "child-edition-scope"] {
        let mut frame = child.frame.clone();
        if case == "child-history-scope" {
            frame.marker_history.identity.push_str("-new");
            for marker in &mut frame.marker_history.markers {
                marker.history.clone_from(&frame.marker_history.identity);
            }
        } else {
            frame.marker_policy.edition = "2".into();
            for marker in &mut frame.marker_history.markers {
                marker.policy_edition.clone_from(&frame.marker_policy.edition);
            }
        }
        recognize_edition(&mut frame);
        invalid(input(&frame, child.genesis).validate(Some(root)), case);
    }
}

fn recognize_edition(frame: &mut Frame) {
    let burn = burn::validate_burn(frame.burn.clone()).unwrap();
    let mut declarations = packages().0.carrier().causes.declarations.clone();
    let declaration = declarations
        .iter_mut()
        .find(|d| d.id.namespace == "marker" && d.id.name == "policy")
        .unwrap();
    declaration.id.edition = frame.marker_policy.edition.parse().unwrap();
    declaration.content = pn_records::constants::marker_policy_declaration(&frame.marker_policy, &burn).unwrap();
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let declarations = pn_records::validate_record(&[], &history, &declarations).unwrap();
    let policy = pn_records::constants::bind_marker_policy(&declarations, frame.marker_policy.clone(), &burn).unwrap();
    let history = burn::validate_marker_history(
        frame.marker_history.clone(),
        &policy,
        &pn_records::test_support::burn::FixtureVerifier,
    )
    .unwrap();
    frame.closure.markers = burn::recognize_markers(&history);
}

/// Claim: Raw marker and recovered-set inputs exercise acceptance predicates unreachable after public admission, including policy mismatch, non-subset recovery, disagreement, initial shape and successor snapshot; existing opening refusals are repeated at this same private boundary.
/// ´claim:history:position-private-acceptance´
/// ´test:unit:position-private-acceptance´
#[test]
fn position_private_acceptance() {
    let root = Input::admitted(&packages().0).unwrap();
    for case in [
        "policy",
        "subset",
        "recovery",
        "index",
        "predecessor",
        "snapshot-missing",
        "snapshot-nonempty",
        "successor-snapshot",
    ] {
        let initial = !matches!(case, "successor-snapshot" | "subset" | "recovery");
        let source = if initial { root.initial } else { root.terminal };
        let mut marker = source.identity().clone();
        let mut accepted = source.accepted().clone();
        match case {
            "policy" => marker.policy_edition.push_str("-changed"),
            "subset" => {
                accepted.insert("absent-record".into());
                marker.accepted = burn::AcceptedSet::CompleteList(accepted.clone());
            }
            "recovery" => marker.accepted = burn::AcceptedSet::CompleteList(BTreeSet::new()),
            "index" => marker.index = 1,
            "predecessor" => marker.predecessor = Some(1),
            "snapshot-missing" => marker.initial_snapshot = None,
            "snapshot-nonempty" => {
                marker.initial_snapshot.as_mut().unwrap().insert(
                    root.frame.marker_history.records[0].address.clone(),
                    root.frame.marker_history.records[0].amount.clone(),
                );
            }
            "successor-snapshot" => marker.initial_snapshot = Some(std::collections::BTreeMap::new()),
            _ => unreachable!(),
        }
        invalid(check_acceptance(&marker, &accepted, &root.frame.marker_policy, initial), case);
    }
    acceptance_refusals(&root);
}
