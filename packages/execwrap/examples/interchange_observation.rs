//! Locked workspace witness for (´[ROOT-amend:observe:refusal-outcomes]´).

use pn_interchange::{Content, ContentKey, Document, Envelope, NamespaceLabel, Registry, Value, Version};

fn main() {
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::INFO).expect("fixture bootstrap");
    assert!(Value::from_canonical_bytes(&[255]).is_err());
    assert_eq!(Value::from_canonical_bytes(&[1]).unwrap(), Value::Unsigned(1));
    assert!(Value::from_canonical_prefix(&[255]).is_err());
    assert!(Value::from_canonical_bytes(&[1, 2]).is_err());
    assert!(Document::from_canonical_bytes(&[1]).is_err());
    assert!(Document::try_from_value(&Value::Unsigned(1)).is_err());
    assert!(ContentKey::new(0).is_err());
    assert!(Envelope::peek(&[]).is_err());
    assert!(pn_interchange::dispatch_prefix(&Registry::new(), &[]).is_err());
    let document = Document::new(
        Envelope::new(NamespaceLabel::parse("org.fixture").unwrap(), Version::new(1, 0, 0)),
        Content::new(),
    );
    assert!(matches!(
        pn_interchange::accept(&Registry::new(), &document),
        pn_interchange::Verdict::Rejected(_)
    ));
    assert!(matches!(
        pn_interchange::dispatch_prefix(&Registry::new(), &document.to_canonical_bytes()).unwrap(),
        pn_interchange::Instrument::Refused(_)
    ));
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        use std::io::Read;
        std::io::stdin().read_exact(&mut [0]).unwrap();
    }
}
