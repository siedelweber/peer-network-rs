use pn_records::{CandidateAct, PublicReference, validate_history};

// Raw, package-owned inputs; every checked object comes from the public validator.
pub fn history(count: usize, mixed: bool) -> (Vec<CandidateAct>, Vec<PublicReference>) {
    let binary = pn_records::test_support::generate(&[0]);
    let paired = pn_records::test_support::generate(&[1]);
    let acts: Vec<_> = (0..count)
        .map(|index| {
            let mut act = if mixed && index % 2 != 0 {
                paired.history[0].clone()
            } else {
                binary.history[0].clone()
            };
            act.id.author = format!("workload-actor-{}", index % 4);
            act.id.sequence = u64::try_from(index).unwrap();
            act.id.family = if mixed && index % 2 != 0 {
                "paired-fixture"
            } else {
                "binary-fixture"
            }
            .into();
            act.authoritative_position = u64::try_from(index).unwrap() + 1;
            for leg in &mut act.legs {
                leg.id.act = act.id.clone();
            }
            act
        })
        .collect();
    let checked = validate_history(&acts, &binary.names).unwrap();
    assert_eq!(checked.acts().len(), count);
    (acts, binary.names)
}

pub fn marker_case(count: usize, commitment: bool) -> pn_records::test_support::burn::BurnCase {
    let mut case = pn_records::test_support::burn::generate(&[0]);
    let initial = case.history.markers[0].clone();
    let successor = case.history.markers[1].clone();
    case.history.markers = (0..count)
        .map(|index| {
            let mut marker = if index == 0 { initial.clone() } else { successor.clone() };
            let index = u64::try_from(index).unwrap();
            marker.name = format!("m{index}");
            marker.index = index;
            marker.history_position = index * 10;
            marker.predecessor = index.checked_sub(1).map(|prior| prior * 10);
            marker
        })
        .collect();
    if commitment {
        pn_records::test_support::burn::committed(&mut case);
    }
    let recognized = pn_records::test_support::burn::recognize(case.clone()).unwrap();
    assert!(recognized.first_refusal().is_none());
    assert_eq!(recognized.markers().len(), count);
    case
}

pub fn marker_policy(case: &pn_records::test_support::burn::BurnCase) -> pn_records::burn::ValidatedPolicy {
    let history = validate_history(&[], &[]).unwrap();
    let declarations = [
        pn_records::Declaration {
            id: pn_records::DeclarationId {
                namespace: "marker".into(),
                name: "policy".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: pn_records::DeclarationContent::MarkerPolicy {
                recipe: "pn-records/marker-policy/v1".into(),
                digest: pn_records::constants::marker_policy_digest(&case.policy),
            },
        },
        pn_records::Declaration {
            id: pn_records::DeclarationId {
                namespace: "deployment".into(),
                name: "genesis".into(),
                edition: 1,
            },
            announced_at: 0,
            effective_at: 0,
            content: pn_records::DeclarationContent::Deployment { genesis_at: 1 },
        },
    ];
    let records = pn_records::validate_record(&[], &history, &declarations).unwrap();
    let burn = pn_records::burn::validate_burn(case.burn.clone()).unwrap();
    pn_records::constants::bind_marker_policy(&records, case.policy.clone(), &burn).unwrap()
}
