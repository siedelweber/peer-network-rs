//! Released title suite observation witness (´[ROOT-inv:observe:noninterference]´).

#[path = "../../verification/tests/common/title_checks.rs"]
mod title_checks;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("list") {
        let names: Vec<_> = pn_testkit::TITLE_CASES.iter().map(|(name, _)| name).collect();
        cli_common::emit(&serde_json::json!(names)).unwrap();
        return;
    }
    let enabled = std::env::args().nth(1).as_deref() != Some("disabled");
    let guard = cli_common::observation::bootstrap(enabled, false, tracing::Level::INFO).expect("configured observation");
    let history: usize = std::env::args()
        .nth(2)
        .expect("one title history index")
        .parse()
        .expect("numeric title history index");
    let (name, words) = pn_testkit::TITLE_CASES.get(history).expect("known title history index");
    let results = [(*name, format!("{:?}", title_checks::check(words)))];
    cli_common::emit(&serde_json::json!(results)).unwrap();
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
}
