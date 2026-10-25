//! Process witness of graph partition with executable-owned observation.
//! (´def:membership:partition´)

fn main() -> std::process::ExitCode {
    let enabled = std::env::args().nth(1).as_deref() != Some("disabled");
    let guard = cli_common::observation::bootstrap(enabled, false, tracing::Level::INFO).expect("controlled observation fixture");
    let mut outputs = Vec::new();
    for words in [&[][..], &[u64::MAX; 8][..]] {
        let case = pn_records::test_support::generate(words);
        let history = pn_records::validate_history(&case.history, &case.names).unwrap();
        let records = pn_records::validate_record(&case.proposals, &history, &[]).unwrap();
        let input = pn_records::assemble_boundary_inputs(&records, case.boundary).unwrap();
        let (graph, blocks) = pn_graph::partition_dependencies(&input).unwrap();
        outputs.push(serde_json::json!({"nodes":graph.node_count(), "edges":graph.edge_count(), "blocks":blocks.iter().map(|block| block.iter().map(|id| id.sequence).collect::<Vec<_>>()).collect::<Vec<_>>()}));
    }
    let result = cli_common::emit(&serde_json::json!({"partition_cases":outputs}));
    drop(guard);
    if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
