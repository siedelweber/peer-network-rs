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
    let mut later = common::act(2, Layout::Binary);
    later.authoritative_position = 2;
    let mut results = Vec::new();
    for dependency in [None, Some(later.id.clone()), Some(common::act(3, Layout::Binary).id)] {
        root.projections.dependency =
            dependency.map_or(DependencyProjection::FullEmpty, |id| DependencyProjection::Full(vec![id]));
        let sequence = [root.clone(), later.clone()];
        let replay = validate_history(&sequence, &names).unwrap();
        let candidate = validate_record(&sequence, &empty, &[]);
        if let Ok(view) = &candidate {
            std::hint::black_box((view.history().acts(), view.history().non_compliance()));
        }
        results.push(serde_json::json!({
            "acts": format!("{:?}", replay.acts()),
            "evidence": format!("{:?}", replay.non_compliance()),
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
