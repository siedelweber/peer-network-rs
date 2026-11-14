use pn_host::binary64::{self as codec, Error};
use pn_records::binary64::{self as model, Carrier, Endpoint, Expected};

fn limits() -> codec::Limits {
    codec::Limits {
        bytes: 1_000_000,
        items: 100_000,
        depth: 64,
        arithmetic: pn_records::numerics::ExactLimits {
            integer_exponent: 1074,
            work: 20_000_000,
            literal_bytes: 1024,
            ..pn_records::numerics::ExactLimits::default()
        },
    }
}
fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../data/binary64-carriers.json")).unwrap()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn named(name: &str) -> Carrier {
    let corpus = corpus();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == name)
        .unwrap();
    codec::decode(&unhex(row["canonical"].as_str().unwrap()), &limits()).unwrap()
}
fn expected(carrier: &Carrier) -> Expected {
    let f = carrier.fields();
    Expected {
        question: f.question.clone(),
        enclosures: f.enclosures,
        adjusted: f.adjusted,
        predicate: f.predicate.clone(),
        polarity: f.polarity,
        consumer: f.consumer,
        grid: f.rungs.as_ref().map(|v| (v.coordinate, v.grid.clone())),
    }
}

fn subnormal_verdicts(rows: &[serde_json::Value]) {
    let mut wide = limits();
    wide.arithmetic.integer_exponent = 1076;
    let polarities = [
        model::Polarity::Proposition,
        model::Polarity::Negation,
        model::Polarity::Uncertified,
    ];
    let mut count = 0;
    for row in rows
        .iter()
        .filter(|row| row["case"].as_str().unwrap().starts_with("subnormal-threshold-"))
    {
        let stated = polarities[usize::try_from(row["expected_relation"].as_u64().unwrap()).unwrap()];
        let decoded = codec::decode(&unhex(row["canonical"].as_str().unwrap()), &wide);
        assert_eq!(
            decoded.as_ref().map(|value| value.fields().tests[0].result),
            Ok(stated),
            "subnormal verdict under wider ceiling {}",
            row["case"]
        );
        count += 1;
    }
    assert_eq!(count, 10, "subnormal threshold rows exercised under wider ceiling");
}

/// Claim: The independent integer corpus reaches named byte, domain, question and prefix refusal classes, exercises threshold and membership branches with their enclosures, including ten subnormal thresholds under an exponent ceiling of 1076, and round-trips valid fragments and their vocabulary codes in unsorted order; this does not establish interval soundness.
/// ´claim:host:binary64-canonical-corpus´
/// ´test:integration:binary64-canonical-corpus´
#[test]
fn binary64_canonical_corpus() {
    let corpus = corpus();
    let rows = corpus["cases"].as_array().unwrap();
    subnormal_verdicts(rows);
    let distinct: std::collections::BTreeSet<_> = rows.iter().map(|r| r["canonical"].as_str().unwrap()).collect();
    assert_eq!(
        distinct.len(),
        usize::try_from(corpus["distinct_inputs"].as_u64().unwrap()).unwrap(),
        "distinct inputs retained"
    );
    assert!(
        rows.windows(2).any(|v| v[0]["case"].as_str() > v[1]["case"].as_str()),
        "corpus reaches codec unsorted"
    );
    for row in rows {
        let bytes = unhex(row["canonical"].as_str().unwrap());
        let decoded = codec::decode(&bytes, &limits());
        if let Some(refusal) = row["refusal"].as_str() {
            assert_eq!(
                decoded.as_ref().err().map(|error| format!("{error:?}")),
                Some(refusal.to_owned()),
                "named refusal {}",
                row["case"]
            );
        } else {
            assert!(decoded.is_ok(), "valid enclosure and verdict {}: {decoded:?}", row["case"]);
            let value = decoded.unwrap();
            assert_eq!(codec::encode(&value).unwrap(), bytes, "canonical bytes {}", row["case"]);
            let fields = value.fields();
            let nodes = row["original_question"][0][1].as_array().unwrap();
            assert_eq!(fields.question.nodes.len(), nodes.len(), "node count {}", row["case"]);
            for (node, source) in fields.question.nodes.iter().zip(nodes) {
                let code = match node {
                    model::Node::Input(..) => 0_u64,
                    model::Node::Coordinate(_) => 1_u64,
                    model::Node::Constant(_) => 2_u64,
                    model::Node::Negate(_) => 3_u64,
                    model::Node::Add(..) => 4_u64,
                    model::Node::Subtract(..) => 5_u64,
                    model::Node::Multiply(..) => 6_u64,
                    model::Node::Divide(..) => 7_u64,
                    model::Node::SquareRoot(_) => 8_u64,
                    model::Node::Logarithm(_) => 9_u64,
                    model::Node::Exponential(_) => 10_u64,
                    model::Node::Sigmoid(_) => 11_u64,
                    model::Node::Tanh(_) => 12_u64,
                    model::Node::Power(..) => 13_u64,
                    model::Node::Derivative(..) => 14_u64,
                    model::Node::Clamp(..) => 15_u64,
                    model::Node::GeneralizedDerivative(..) => 16_u64,
                };
                assert_eq!(code, source[0].as_u64().unwrap(), "node vocabulary {}", row["case"]);
            }
            let consumers = [
                model::Consumer::Free,
                model::Consumer::Value,
                model::Consumer::Map,
                model::Consumer::Residual,
                model::Consumer::Rung,
                model::Consumer::Fixed,
                model::Consumer::Local,
            ];
            let outcomes = [
                model::Outcome::Completed,
                model::Outcome::InvalidInput,
                model::Outcome::InvalidEvidence,
                model::Outcome::Unsupported,
                model::Outcome::TargetNotCertifiable,
                model::Outcome::Resource,
                model::Outcome::Interrupted,
            ];
            let relations = [model::Relation::Equal, model::Relation::Less, model::Relation::AtMost];
            assert_eq!(
                fields.consumer,
                consumers[usize::try_from(row["consumer"].as_u64().unwrap()).unwrap()],
                "consumer vocabulary {}",
                row["case"]
            );
            assert_eq!(
                fields.outcome,
                outcomes[usize::try_from(row["outcome"].as_u64().unwrap()).unwrap()],
                "outcome vocabulary {}",
                row["case"]
            );
            for (hypothesis, code) in fields.question.hypotheses.iter().zip(row["relations"].as_array().unwrap()) {
                assert_eq!(
                    hypothesis.relation,
                    relations[usize::try_from(code.as_u64().unwrap()).unwrap()],
                    "relation vocabulary {}",
                    row["case"]
                );
            }
        }
    }
}

/// Claim: Explicit expected-context comparison refuses independent substitutions of inputs, domain, expression, actual enclosure, polarity, permissions, threshold and grid even when the supplied carrier is internally consistent; this does not establish a consumer's derivation of that context.
/// ´claim:host:binary64-expected-question-binding´
/// ´test:integration:binary64-expected-question-binding´
#[test]
fn binary64_expected_question_binding() {
    let original = named("original-not-rounded");
    let mut query = expected(&original);
    original.bind(&query).unwrap();
    query.question.inputs[0].source = b"9007199254740992".to_vec();
    assert_eq!(
        original.bind(&query),
        Err(model::Error::OriginalInputs),
        "original-input substitution"
    );
    let value = named("contained");
    let mut query = expected(&value);
    query.enclosures = Some((
        value.fields().enclosures.unwrap().0,
        model::Enclosure::new(Endpoint::new(0).unwrap(), true, Endpoint::new(0).unwrap(), true).unwrap(),
    ));
    assert_eq!(
        value.bind(&query),
        Err(model::Error::ActualEnclosure),
        "actual-enclosure substitution"
    );
    let mut query = expected(&value);
    query.polarity = model::Polarity::Negation;
    assert_eq!(value.bind(&query), Err(model::Error::Polarity), "polarity substitution");
    let mut query = expected(&value);
    query.adjusted = !query.adjusted;
    assert_eq!(
        value.bind(&query),
        Err(model::Error::Adjustment),
        "adjustment permission substitution"
    );
    let mut query = expected(&value);
    query.consumer = model::Consumer::Fixed;
    assert_eq!(
        value.bind(&query),
        Err(model::Error::Consumer),
        "consumer permission substitution"
    );
    let mut query = expected(&value);
    query.question.nodes[0] = model::Node::Constant(model::Fraction::new("1".into(), "1".into(), limits().arithmetic).unwrap());
    assert_eq!(value.bind(&query), Err(model::Error::Question), "query substitution");
    let fixed = named("threshold-1-3ff0000000000000");
    let mut query = expected(&fixed);
    query.predicate = model::Predicate::AtMost(model::Fraction::new("2".into(), "1".into(), limits().arithmetic).unwrap());
    assert_eq!(
        fixed.bind(&query),
        Err(model::Error::Predicate),
        "original threshold substitution"
    );
    let mut substitution = fixed.fields().clone();
    substitution.predicate = model::Predicate::Membership;
    substitution.enclosures = value.fields().enclosures;
    assert_eq!(
        Carrier::new(substitution, limits().arithmetic),
        Err(model::Error::Consumer),
        "original-threshold forbids adjusted-enclosure substitution"
    );
    let mut query = expected(&fixed);
    query.predicate = model::Predicate::Membership;
    query.enclosures = Some((value.fields().enclosures.unwrap().0, value.fields().enclosures.unwrap().0));
    assert_eq!(
        fixed.bind(&query),
        Err(model::Error::ActualEnclosure),
        "original-threshold forbids adjusted-enclosure substitution"
    );
    let rung = named("accepted-zero");
    let mut query = expected(&rung);
    query.question.coordinates[0].upper_included = false;
    assert_eq!(rung.bind(&query), Err(model::Error::Question), "complete domain substitution");
    let mut query = expected(&rung);
    query.grid = None;
    assert_eq!(rung.bind(&query), Err(model::Error::RungPrefix), "declared grid substitution");
    let mut query = expected(&value);
    query.question.hypotheses.push(model::Hypothesis {
        relation: model::Relation::Equal,
        left: 0,
        right: 0,
    });
    assert_eq!(value.bind(&query), Err(model::Error::Question), "hypothesis substitution");
}

fn preliminary_ceiling(corpus: &serde_json::Value, arithmetic: &codec::Limits) {
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == "root-not-last")
        .unwrap();
    let bytes = unhex(row["canonical"].as_str().unwrap());
    assert_eq!(
        codec::decode(&bytes, &limits()),
        Err(Error::Structure(model::Error::CanonicalNodes)),
        "question refuses before cumulative constant reading"
    );
    assert_eq!(
        codec::decode(&bytes, arithmetic),
        Err(Error::Structure(model::Error::Resource)),
        "preliminary fraction ceiling precedes question refusal"
    );
}

/// Claim: The finite endpoint constructor orders signed subnormal and normal patterns by the integer key, refuses negative zero and every sampled non-finite class, and the reader accepts each independently counted byte, item and depth limit and refuses one below it; a carrier and its decoder refuse an insufficient arithmetic ceiling and accept the declared test ceiling, with the decoder's preliminary fraction ceiling independently preceding a malformed question's refusal.
/// ´claim:host:binary64-finite-and-bounded´
/// ´test:integration:binary64-finite-and-bounded´
#[test]
fn binary64_finite_and_bounded() {
    for bits in [
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0xfff8_0000_0000_0001,
    ] {
        assert_eq!(
            Endpoint::new(bits),
            Err(model::Error::NonFinite),
            "non-finite-pattern refusal"
        );
    }
    assert_eq!(
        Endpoint::new(1 << 63),
        Err(model::Error::NegativeZero),
        "negative-zero refusal"
    );
    let patterns = [
        0xffef_ffff_ffff_ffff,
        0x8010_0000_0000_0000,
        0x8000_0000_0000_0001,
        0,
        1,
        0x0010_0000_0000_0000,
        0x7fef_ffff_ffff_ffff,
    ];
    let values: Vec<_> = patterns.into_iter().map(|b| Endpoint::new(b).unwrap()).collect();
    assert!(values.windows(2).all(|v| v[0] < v[1]), "integer endpoint ordering");
    let bytes = codec::encode(&named("contained")).unwrap();
    let corpus = corpus();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["case"] == "contained")
        .unwrap();
    let carrier = named("contained");
    let mut arithmetic = limits();
    arithmetic.arithmetic.work = 1;
    assert_eq!(
        Carrier::new(carrier.fields().clone(), arithmetic.arithmetic.clone()),
        Err(model::Error::Resource),
        "carrier arithmetic ceiling"
    );
    assert_eq!(
        codec::decode(&bytes, &arithmetic),
        Err(Error::Structure(model::Error::Resource)),
        "decoder arithmetic ceiling"
    );
    assert!(
        Carrier::new(carrier.fields().clone(), limits().arithmetic).is_ok(),
        "carrier test arithmetic ceiling"
    );
    assert!(codec::decode(&bytes, &limits()).is_ok(), "decoder test arithmetic ceiling");
    preliminary_ceiling(&corpus, &arithmetic);
    let counts = [
        bytes.len(),
        usize::try_from(row["reader_items"].as_u64().unwrap()).unwrap(),
        usize::try_from(row["reader_depth"].as_u64().unwrap()).unwrap(),
    ];
    for (field, count) in counts.into_iter().enumerate() {
        let mut bound = limits();
        for reduction in 0..2 {
            match field {
                0 => bound.bytes = count - reduction,
                1 => bound.items = count - reduction,
                _ => bound.depth = count - reduction,
            }
            let result = codec::decode(&bytes, &bound);
            if reduction == 0 {
                assert!(result.is_ok(), "reader bound inclusive limit {field}: {result:?}");
            } else {
                assert_eq!(result, Err(Error::Resource), "reader bound one past {field}");
            }
        }
    }
}
