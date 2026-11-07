use std::{fmt::Write, path::Path};

pub(super) fn name() -> String {
    std::env::var("PN_BENCH_POINT").unwrap()
}
pub(super) fn internal() -> String {
    let size: usize = std::env::var("PN_BENCH_SIZE").unwrap().parse().unwrap();
    let variant = std::env::var("PN_BENCH_VARIANT").unwrap();
    let name = name();
    if name.starts_with("partition-") {
        format!("B2-partition-m{size}-shape{variant}")
    } else if name.starts_with("transport-") {
        let (dense, enclosed) = match variant.as_str() {
            "sparse-exact" => (false, false),
            "sparse-enclosed" => (false, true),
            "dense-exact" => (true, false),
            "dense-enclosed" => (true, true),
            _ => panic!("unknown transport variant"),
        };
        format!("B4-transport-n{size}-dense{dense}-enclosed{enclosed}")
    } else if name.starts_with("title-") {
        format!("B16-title-m{size}")
    } else if name.starts_with("compile-actors-") {
        format!("B3-compile-n{size}-{variant}")
    } else if name.starts_with("compile-acts-") {
        format!("B3-compile-m{size}-{variant}")
    } else if name.starts_with("solve-") {
        format!("B6-solve-n{size}-{variant}")
    } else if name.starts_with("replay-") {
        format!("B7-replay-n{size}-{variant}")
    } else if name.starts_with("fence-") {
        format!("B5-fence-{variant}-bits{size}")
    } else if name.starts_with("admit-") {
        format!("B8-admit-m{size}-{variant}")
    } else if name.starts_with("trials-") {
        format!("B9-trials-s{size}")
    } else if name.starts_with("scalar-") {
        format!("B10-{variant}-cap{size}")
    } else {
        panic!("unknown owned workload")
    }
}
fn string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < ' ' => write!(out, "\\u{:04x}", u32::from(c)).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn numeric(text: &str, key: &str) -> String {
    text.split_whitespace()
        .filter_map(|v| v.strip_prefix(&format!("{key}=")))
        .find(|v| v.parse::<u64>().is_ok())
        .map_or_else(|| "null".into(), str::to_owned)
}
fn seconds(text: &str, key: &str) -> String {
    text.split_whitespace()
        .filter_map(|v| v.strip_prefix(&format!("{key}=")))
        .find(|v| v.parse::<f64>().is_ok_and(|f| f.is_finite() && f >= 0.0))
        .map_or_else(|| "null".into(), str::to_owned)
}
fn identity(header: &str) -> String {
    let revision = header
        .split_whitespace()
        .find_map(|value| value.strip_prefix("procedure_revision="));
    let recipe = header.split_whitespace().find_map(|value| value.strip_prefix("recipe="));
    if name().starts_with("solve-") || name().starts_with("replay-") {
        assert_eq!(revision, Some("memoized-dyadic-v4"));
        assert_eq!(recipe, Some("scaling-workloads/memoized-dyadic-v4"));
    }
    format!(
        "{{\"procedure_revision\":{},\"recipe_edition\":{},",
        revision.map_or_else(|| "null".into(), string),
        recipe.map_or_else(|| "null".into(), string)
    )
}
pub(super) fn finish(output: &Path, mode: &str) {
    let evidence = std::fs::read_to_string(output.join(format!("{}.txt", internal()))).unwrap();
    let header = evidence.lines().next().unwrap();
    let refused = header.contains("outcome=REFUSED") || header.contains("outcome=Err(");
    assert!(refused || header.contains("outcome=PASS") || header.contains("outcome=Ok("));
    let mut dimensions = String::from("{");
    for key in [
        "N",
        "M",
        "Z",
        "H",
        "S",
        "K",
        "B",
        "M_solve",
        "M_replay",
        "precision_rounds",
        "primitive_count",
        "setup_work",
        "map_work",
        "final_check_work",
        "driver_work",
        "solve_work",
        "replay_work",
        "work",
        "primitive_work",
        "oracle_work_limit",
        "diagnostic_transcript_bytes",
        "diagnostic_bytes",
        "maximum_work",
        "maximum_solve_work",
        "maximum_replay_work",
        "maximum_iterations",
        "maximum_cells",
    ] {
        write!(dimensions, "{}:{},", string(key), numeric(&evidence, key)).unwrap();
    }
    write!(
        dimensions,
        "\"unavailable_reason\":{} }}",
        string(
            "null means not exposed by this operation or no produced transcript; never zero; diagnostic bytes are not heap bytes"
        )
    )
    .unwrap();
    let receipt = format!(
        "{{\"name\":{},\"size\":{},\"variant\":{},\"mode\":{},\"run\":{},\"correctness\":\"passed\",\"outcome\":{},\"reason\":{},\"dimensions\":{},\"setup_s\":{},\"setup_scope\":\"reported setup component; constructor then fresh-context when available; process wall retains all setup and correctness\",\"teardown_s\":null,\"teardown_scope\":\"owned output destruction is timed by Criterion; no separate teardown clock\",\"bit_lengths\":null,\"bit_lengths_reason\":\"not exposed by these public counters\",\"memory\":null,\"memory_reason\":\"no owned allocator counter; runner records container cgroup scope\",\"limits_and_evidence\":{} }}",
        string(&name()),
        std::env::var("PN_BENCH_SIZE").unwrap().parse::<usize>().unwrap(),
        string(&std::env::var("PN_BENCH_VARIANT").unwrap()),
        string(mode),
        string(&std::env::var("PN_BENCH_RUN").unwrap()),
        string(if refused { "refused" } else { "passed" }),
        string(if refused { header } else { "" }),
        dimensions,
        ["setup_s", "construction_s", "fresh_setup_s"]
            .iter()
            .map(|key| seconds(&evidence, key))
            .find(|v| v != "null")
            .unwrap_or_else(|| "null".into()),
        string(&evidence)
    );
    let receipt = identity(header) + receipt.strip_prefix('{').unwrap();
    std::fs::write(std::env::var_os("PN_BENCH_RECEIPT").unwrap(), receipt).unwrap();
}
