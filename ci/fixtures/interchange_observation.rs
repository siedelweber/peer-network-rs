use pn_interchange::{Content, Document, Envelope, NamespaceLabel, Registry, Value, Version};

fn main() {
    let guard = cli_common::observation::bootstrap(true, false, tracing::Level::INFO).expect("fixture bootstrap");
    assert!(Value::from_canonical_bytes(&[255]).is_err());
    assert_eq!(Value::from_canonical_bytes(&[1]).unwrap(), Value::Unsigned(1));
    let document = Document::new(
        Envelope::new(NamespaceLabel::parse("org.fixture").unwrap(), Version::new(1, 0, 0)),
        Content::new(),
    );
    assert!(matches!(pn_interchange::accept(&Registry::new(), &document), pn_interchange::Verdict::Rejected(_)));
    drop(guard);
}
