//! Independently authored structural bytes, not an admission certificate.
use super::{base, wire_limits};

fn text(value: &str) -> Vec<u8> {
    let size = u8::try_from(value.len()).unwrap();
    let mut bytes = if size < 24 { vec![0x60 + size] } else { vec![0x78, size] };
    bytes.extend_from_slice(value.as_bytes());
    bytes
}
fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let size = u8::try_from(items.len()).unwrap();
    let mut bytes = if size < 24 { vec![0x80 + size] } else { vec![0x98, size] };
    for item in items {
        bytes.extend_from_slice(item);
    }
    bytes
}
fn exact() -> Vec<u8> {
    array(&[text("1"), array(&[text("1"), text("1")])])
}
fn limits() -> Vec<u8> {
    array(&vec![text("1"); 71])
}
fn numeraire() -> Vec<u8> {
    array(&[text("test-unit"), array(&[array(&[text("1"), text("1")]), text("burn")])])
}
fn edition() -> Vec<u8> {
    array(&[text("test"), text("constants"), text("1")])
}
fn procedure(boundary: &str) -> Vec<u8> {
    array(&[
        edition(),
        text(boundary),
        text("procedure"),
        text("nrz-cas"),
        vec![0x80],
        vec![0x81, 0],
        vec![0x81, 0],
        array(&[exact()]),
        exact(),
        text("1"),
        text("1"),
        text("1"),
        text("1"),
        exact(),
        vec![0xf6],
        vec![0xf6],
    ])
}
fn effective(boundary: &str) -> Vec<u8> {
    array(&[text(boundary), exact(), exact(), numeraire(), exact()])
}
fn schedule(boundary: &str) -> Vec<u8> {
    let initialization = vec![0x85, 0xf6, 0xf6, 0xf6, 0xf6, 0xf6];
    let declaration = array(&[
        text("controller"),
        text("0"),
        initialization,
        numeraire(),
        vec![0x81, 0],
        array(&[array(&[text("4")]), text("1"), text("1")]),
    ]);
    array(&[declaration, effective(boundary), vec![0x80]])
}
fn statement(boundary: &str) -> Vec<u8> {
    array(&[
        array(&[text("1"), text("0"), text("1"), text("clock")]),
        text("0"),
        text(boundary),
        vec![0x81, 1],
        text("determination"),
    ])
}
fn standing() -> Vec<u8> {
    array(&[vec![0x84, 0xa0, 0x80, 0xf6, 0x80], vec![0x80], text("0"), text("0")])
}
fn reproduction(boundary: &str) -> Vec<u8> {
    let realization = array(&[
        text("test"),
        vec![0x41, 1],
        vec![0x41, 2],
        vec![0x41, 3],
        vec![0x41, 4],
        vec![0x41, 5],
        vec![0x83, 1, 0x41, 6, 0x41, 7],
    ]);
    let evidence = array(&[
        text("lineage"),
        text("settlement"),
        vec![0xf6],
        vec![0xf6],
        vec![0xf6],
        vec![0xf6],
        vec![0xf6],
    ]);
    let burn = array(&[
        text("regtest"),
        text("burn"),
        text("test"),
        text(boundary),
        vec![0x80],
        vec![0xa0],
        vec![0xf6],
        vec![0xf6],
        evidence,
    ]);
    let parameters = array(&[
        text(boundary),
        edition(),
        numeraire(),
        vec![0x80],
        vec![0xa0],
        text("decay"),
        text("bleed"),
        vec![0x80],
    ]);
    let price = array(&[exact(), numeraire(), exact(), vec![0x81, 0], vec![0xf6]]);
    let final_procedure = array(&[procedure(boundary), limits(), text("1")]);
    let policy = array(&[
        text("policy"),
        text("regtest"),
        text("burn"),
        text("1"),
        text("1"),
        text("operator"),
        vec![0xf5],
        text("lineage"),
        text("accepted"),
        vec![0x81, 0],
        vec![0x81, 0],
        text("genesis"),
        text("0"),
    ]);
    let history = array(&[text("regtest"), vec![0x80], vec![0x80]]);
    let recognition = array(&[
        array(&[
            text("policy"),
            text("regtest"),
            text("burn"),
            text("lineage"),
            text("accepted"),
            text("fixture"),
        ]),
        vec![0x80],
        vec![0xf6],
    ]);
    array(&[
        realization,
        burn,
        parameters,
        price,
        final_procedure,
        policy,
        history,
        recognition,
        vec![0x80],
    ])
}
fn bytes() -> Vec<u8> {
    let accepted = array(&[
        vec![0x80],
        vec![0x80],
        array(&[
            array(&[vec![0x80], statement("1"), vec![0x80]]),
            array(&[vec![0x80], statement("2"), vec![0x80]]),
        ]),
    ]);
    let ledger = vec![0x82, 0x84, 0x80, 0xa0, 0xa0, 0xa0, 0x84, 0x80, 0xa0, 0xa0, 0xa0];
    let projection = |boundary| {
        array(&[
            vec![0x80],
            vec![0xa0],
            vec![0x80],
            array(&[text(boundary), edition(), vec![0xa0]]),
        ])
    };
    let support = |boundary| {
        array(&[
            text(boundary),
            vec![0xa0],
            vec![0xa0],
            vec![0xa0],
            vec![0xa0],
            vec![0xa0],
            text("0"),
        ])
    };
    let finality = |boundary| array(&[standing(), array(&[effective(boundary), vec![0x80], vec![0xf6], vec![0x80]])]);
    let closure = |boundary| {
        array(&[
            array(&[text(boundary), vec![0xa0], vec![0x80], vec![0x80], vec![0x80]]),
            schedule(boundary),
            schedule(boundary),
        ])
    };
    let reproduction = array(&[
        vec![0x80],
        vec![0x80],
        array(&[limits(), text("1"), text("1")]),
        array(&[reproduction("1"), reproduction("2")]),
    ]);
    let fields = [
        text("org.peer-network.test.publication"),
        vec![0x83, 1, 0, 0],
        accepted,
        ledger,
        array(&[projection("1"), projection("2")]),
        array(&[support("1"), support("2")]),
        array(&[finality("1"), finality("2")]),
        array(&[closure("1"), closure("2")]),
        reproduction,
    ];
    let mut result = vec![0xa9];
    for (key, value) in fields.iter().enumerate() {
        result.push(u8::try_from(key).unwrap());
        result.extend_from_slice(value);
    }
    result
}

/// Claim: Independently authored canonical CBOR for every section of two untrusted boundaries is read and written byte for byte, without treating the structural vector as admitted evidence.
/// ´claim:publication:independent-structural-bytes´
/// ´test:integration:publication-independent-bytes´
#[test]
fn publication_independent_bytes() {
    let expected = bytes();
    let disclosure = super::decode_exact(&expected);
    assert_eq!(disclosure.frames.len(), 2);
    assert_eq!(disclosure.frames[0].parameters.boundary, 1);
    assert_eq!(disclosure.frames[1].parameters.boundary, 2);
    let encoded = pn_host::publication::encode(&disclosure, &mut base::numeric(), wire_limits()).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(super::decode_exact(&encoded), disclosure);
}
