use documents::{Finding, FindingKind, Report};

/// Claim: Public reports preserve every finding's kind and path, while empty optional collections stay absent.
/// ´claim:render:public-report-carrier´
/// ´test:integration:report-carrier´
#[test]
fn report_carrier() {
    let report = Report {
        findings: vec![Finding {
            kind: FindingKind::StaleDocument,
            path: "docs/quoted\"name.md".into(),
        }],
        ..Report::default()
    };
    let encoded = serde_json::to_value(&report).expect("report serializes");
    assert_eq!(
        encoded,
        serde_json::json!({"findings": [{"kind": "stale_document", "path": "docs/quoted\"name.md"}]})
    );
}
