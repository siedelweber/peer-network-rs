use cli_common::{ControlPlaneRecord, ControlPlaneRecordKind};

/// Claim: Caller-visible status text round-trips through the public JSON record without becoming extra records.
/// ´claim:cli:public-control-record-roundtrip´
/// ´test:integration:control-record-roundtrip´
#[test]
fn control_record_roundtrip() {
    let record = ControlPlaneRecord::status("caller", "quoted \"line\"\nnext λ");
    let bytes = serde_json::to_vec(&record).expect("record serializes");
    assert!(!bytes.contains(&b'\n'));
    let decoded: ControlPlaneRecord = serde_json::from_slice(&bytes).expect("one JSON record");
    assert_eq!(decoded, record);
    assert_eq!(decoded.kind, ControlPlaneRecordKind::Status);
    assert_eq!(decoded.fields, None);
}
