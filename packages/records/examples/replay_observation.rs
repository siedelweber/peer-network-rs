//! Finalized-history observation witness (´[ROOT-inv:observe:noninterference]´).

#[path = "../tests/common/mod.rs"]
mod common;

use cli_common::observation::bootstrap;
use pn_records::{DependencyProjection, Layout, validate_history, validate_record};

fn main() {
    let enabled = std::env::args().nth(1).as_deref() != Some("disabled");
    let guard = bootstrap(enabled, false, tracing::Level::INFO).expect("configured observation");
    let names = [common::named("left"), common::named("right")];
    let empty = common::resolved();
    let mut root = common::act(1, Layout::Paired);
    root.authoritative_position = 1;
    root.logical_time = 1;
    let mut later = common::act(2, Layout::Binary);
    later.authoritative_position = 2;
    later.logical_time = 2;
    let mut results = Vec::new();
    for case in 0..8 {
        let mut root = root.clone();
        let mut later = later.clone();
        let dependency = match case {
            1 => Some(later.id.clone()),
            2 => Some(common::act(3, Layout::Binary).id),
            _ => None,
        };
        root.projections.dependency =
            dependency.map_or(DependencyProjection::FullEmpty, |id| DependencyProjection::Full(vec![id]));
        match case {
            3 => root.logical_time = 7,
            4 => {
                root.logical_time = 7;
                root.projections.dependency = DependencyProjection::Tombstoned((5, 3));
            }
            5 => {
                root.finalization_epoch = 1;
                root.authoritative_position = 2;
                later.finalization_epoch = 2;
                later.authoritative_position = 1;
                later.projections.dependency = DependencyProjection::Full(vec![root.id.clone()]);
            }
            6 => root.body.asserted_parents = vec![later.id.clone()],
            7 => root.body.asserted_parents = vec![common::act(3, Layout::Binary).id],
            _ => {}
        }
        let sequence = [root.clone(), later.clone()];
        let replay = validate_history(&sequence, &names).unwrap();
        let candidate = validate_record(&sequence, &empty, &[]);
        if let Ok(view) = &candidate {
            std::hint::black_box((view.history().acts(), view.history().non_compliance()));
        }
        results.push(serde_json::json!({
            "acts": format!("{:?}", replay.acts()),
            "evidence": format!("{:?}", replay.non_compliance()),
            "time_evidence": format!("{:?}", replay.time_evidence()),
            "parent_faults": format!("{:?}", replay.parent_faults()),
            "unavailable_dependencies": format!("{:?}", replay.unavailable_dependencies()),
            "candidate": format!("{candidate:?}"),
            "violations": replay.non_compliance().len(),
            "admitted": candidate.is_ok(),
        }));
    }
    cli_common::emit(&results).unwrap();
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
}
