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

/// Claim: The independent integer corpus reaches named byte, domain, question and prefix refusal classes, exercises threshold and membership branches with their enclosures, including ten subnormal thresholds under an exponent ceiling of 1076, and round-trips both explicitly selected editions in unsorted order, including positive-attempt endings, binding and ordered refusals; this does not establish interval soundness.
/// ´claim:host:binary64-canonical-corpus´
/// ´test:integration:binary64-canonical-corpus´
#[test]
fn binary64_canonical_corpus() {
    let corpus = corpus();
    let rows = corpus["cases"].as_array().unwrap();
    subnormal_verdicts(rows);
    for row in rows.iter().filter(|r| {
        let name = r["case"].as_str().unwrap();
        name.starts_with("positive-order-") || name.starts_with("positive-within-")
    }) {
        second_edition(row);
    }
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
        if row["edition"] == 2 {
            second_edition(row);
            continue;
        }
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
            assert_eq!(
                codec::decode_v2(&bytes, &limits()),
                Err(Error::UnknownCode),
                "first edition refused by second decoder {}",
                row["case"]
            );
            assert_eq!(codec::encode(&value).unwrap(), bytes, "canonical bytes {}", row["case"]);
            let fields = value.fields();
            node_codes(fields, row);
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

fn second_edition(row: &serde_json::Value) {
    let bytes = unhex(row["canonical"].as_str().unwrap());
    let decoded = codec::decode_v2(&bytes, &limits());
    if let Some(refusal) = row["refusal"].as_str() {
        assert_eq!(
            decoded.as_ref().err().map(|e| format!("{e:?}")),
            Some(refusal.to_owned()),
            "positive named refusal {}",
            row["case"]
        );
    } else {
        assert!(decoded.is_ok(), "positive valid {}: {decoded:?}", row["case"]);
        let carrier = decoded.unwrap();
        assert_eq!(
            codec::encode_v2(&carrier).unwrap(),
            bytes,
            "positive canonical bytes {}",
            row["case"]
        );
        assert_eq!(
            codec::decode(&bytes, &limits()),
            Err(Error::UnknownCode),
            "second edition refused by first decoder {}",
            row["case"]
        );
        let f = carrier.fields();
        let mut small = limits();
        small.arithmetic.work = 1;
        assert_eq!(
            model::CarrierV2::new(f.clone(), small.arithmetic.clone()),
            Err(model::ErrorV2::Shared(model::Error::Resource)),
            "positive carrier arithmetic ceiling {}",
            row["case"]
        );
        assert_eq!(
            codec::decode_v2(&bytes, &small),
            Err(Error::Structure(model::Error::Resource)),
            "positive decoder arithmetic ceiling {}",
            row["case"]
        );
        let ending = match f.ending {
            model::Ending::Complete => serde_json::json!([0]),
            model::Ending::Anchor => serde_json::json!([1]),
            model::Ending::Operational(cause) => serde_json::json!([2, cause]),
        };
        assert_eq!(ending, row["outcome"], "positive ending {}", row["case"]);
        second_binding(&carrier, row);
        if row["case"] == "positive-anchor-identical" {
            cumulative_budget(f);
        }
        let polarity = f.polarity.map(|p| match p {
            model::Polarity::Proposition => 0,
            model::Polarity::Negation => 1,
            model::Polarity::Uncertified => 2,
        });
        assert_eq!(
            serde_json::to_value(polarity).unwrap(),
            row["expected_relation"],
            "positive polarity {}",
            row["case"]
        );
    }
}

fn node_codes(fields: &model::Fields, row: &serde_json::Value) {
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
}

fn second_binding(carrier: &model::CarrierV2, row: &serde_json::Value) {
    let f = carrier.fields();
    let expected = model::ExpectedV2 {
        question: f.question.clone(),
        enclosures: f.enclosures,
        adjusted: f.adjusted,
        predicate: f.predicate.clone(),
        polarity: f.polarity,
        consumer: f.consumer,
        grid: f.rungs.as_ref().map(|r| (r.coordinate, r.grid.clone())),
    };
    assert_eq!(carrier.bind(&expected), Ok(()), "positive original context {}", row["case"]);
    let mut changed = expected.clone();
    changed.question.inputs.push(model::Input {
        name: "other".into(),
        source: Vec::new(),
        value: model::Data::Absent,
    });
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::OriginalInputs)),
        "positive input binding {}",
        row["case"]
    );
    let mut changed = expected.clone();
    changed.question.hypotheses.push(model::Hypothesis {
        relation: model::Relation::Equal,
        left: 0,
        right: 0,
    });
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::Question)),
        "positive hypothesis binding {}",
        row["case"]
    );
    second_members(carrier, &expected, row);
    if let Some(r) = &f.rungs {
        let mut changed = expected.clone();
        changed.grid = Some((r.coordinate + 1, r.grid.clone()));
        assert_eq!(
            carrier.bind(&changed),
            Err(model::ErrorV2::Shared(model::Error::RungPrefix)),
            "positive pinned coordinate binding {}",
            row["case"]
        );
    }
}

fn second_members(carrier: &model::CarrierV2, expected: &model::ExpectedV2, row: &serde_json::Value) {
    second_values(carrier, expected, row);
    let mut changed = expected.clone();
    let e = model::Enclosure::new(Endpoint::new(0).unwrap(), true, Endpoint::new(0).unwrap(), true).unwrap();
    changed.enclosures = if expected.enclosures.is_some() { None } else { Some((e, e)) };
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::ActualEnclosure)),
        "positive enclosure binding {}",
        row["case"]
    );
    let mut changed = expected.clone();
    changed.predicate = if expected.predicate == model::Predicate::Membership {
        model::Predicate::AtMost(model::Fraction::new("1".into(), "1".into(), limits().arithmetic).unwrap())
    } else {
        model::Predicate::Membership
    };
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::Predicate)),
        "positive predicate binding {}",
        row["case"]
    );
    let mut changed = expected.clone();
    changed.polarity = if expected.polarity.is_some() {
        None
    } else {
        Some(model::Polarity::Proposition)
    };
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::Polarity)),
        "positive polarity binding including null {}",
        row["case"]
    );
    let mut changed = expected.clone();
    changed.adjusted = !expected.adjusted;
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::Adjustment)),
        "positive adjustment binding {}",
        row["case"]
    );
    let mut changed = expected.clone();
    changed.consumer = if expected.consumer == model::Consumer::Rung {
        model::Consumer::Free
    } else {
        model::Consumer::Rung
    };
    assert_eq!(
        carrier.bind(&changed),
        Err(model::ErrorV2::Shared(model::Error::Consumer)),
        "positive consumer binding {}",
        row["case"]
    );
    if let Some((coordinate, grid)) = &expected.grid {
        let mut changed = expected.clone();
        let mut grid = grid.clone();
        grid[0] = model::Fraction::new("17".into(), "1".into(), limits().arithmetic).unwrap();
        changed.grid = Some((*coordinate, grid));
        assert_eq!(
            carrier.bind(&changed),
            Err(model::ErrorV2::Shared(model::Error::RungPrefix)),
            "positive same-coordinate grid-value binding {}",
            row["case"]
        );
    }
}

fn second_values(carrier: &model::CarrierV2, expected: &model::ExpectedV2, row: &serde_json::Value) {
    if let Some(polarity) = expected.polarity {
        let mut changed = expected.clone();
        changed.polarity = Some(if polarity == model::Polarity::Proposition {
            model::Polarity::Negation
        } else {
            model::Polarity::Proposition
        });
        assert_eq!(
            carrier.bind(&changed),
            Err(model::ErrorV2::Shared(model::Error::Polarity)),
            "positive stated-polarity value binding {}",
            row["case"]
        );
    }
    if let Some((original, actual)) = expected.enclosures {
        let mut changed = expected.clone();
        let zero = model::Enclosure::new(Endpoint::new(0).unwrap(), true, Endpoint::new(0).unwrap(), true).unwrap();
        let one = model::Enclosure::new(
            Endpoint::new(0x3ff0_0000_0000_0000).unwrap(),
            true,
            Endpoint::new(0x3ff0_0000_0000_0000).unwrap(),
            true,
        )
        .unwrap();
        changed.enclosures = Some((original, if actual == zero { one } else { zero }));
        assert_eq!(
            carrier.bind(&changed),
            Err(model::ErrorV2::Shared(model::Error::ActualEnclosure)),
            "positive actual-enclosure value binding {}",
            row["case"]
        );
    }
    if let model::Predicate::AtMost(value) = &expected.predicate {
        let mut changed = expected.clone();
        let numerator = if value.parts() == ("2", "1") { "3" } else { "2" };
        changed.predicate =
            model::Predicate::AtMost(model::Fraction::new(numerator.into(), "1".into(), limits().arithmetic).unwrap());
        assert_eq!(
            carrier.bind(&changed),
            Err(model::ErrorV2::Shared(model::Error::Predicate)),
            "positive threshold value binding {}",
            row["case"]
        );
    }
    if let Some((coordinate, grid)) = &expected.grid {
        let mut changed = expected.clone();
        let mut longer = grid.clone();
        longer.push(model::Fraction::new("0".into(), "1".into(), limits().arithmetic).unwrap());
        changed.grid = Some((*coordinate, longer));
        assert_eq!(
            carrier.bind(&changed),
            Err(model::ErrorV2::Shared(model::Error::RungPrefix)),
            "positive grid-length binding {}",
            row["case"]
        );
    }
}

fn least_budget(fields: &model::FieldsV2) -> pn_records::numerics::ExactLimits {
    let mut limits = limits().arithmetic;
    let mut lower = 0;
    let mut upper = limits.work;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        limits.work = middle;
        match model::CarrierV2::new(fields.clone(), limits.clone()) {
            Ok(_) => upper = middle,
            Err(model::ErrorV2::Shared(model::Error::Resource)) => lower = middle + 1,
            other => panic!("budget search preserves the valid carrier: {other:?}"),
        }
    }
    limits.work = upper;
    assert!(
        model::CarrierV2::new(fields.clone(), limits.clone()).is_ok(),
        "least cumulative work admits"
    );
    limits
}

fn cumulative_budget(fields: &model::FieldsV2) {
    let least = least_budget(fields);
    let mut below = least.clone();
    below.work -= 1;
    assert_eq!(
        model::CarrierV2::new(fields.clone(), below),
        Err(model::ErrorV2::Shared(model::Error::Resource)),
        "cumulative work one below least refuses"
    );
    let mut work = Vec::new();
    for count in 0..3 {
        let mut prefix = fields.clone();
        prefix.tests.truncate(count);
        prefix.rungs.as_mut().unwrap().rows.truncate(count);
        prefix.ending = model::Ending::Operational(1);
        prefix.polarity = None;
        work.push(least_budget(&prefix).work);
    }
    work.push(least.work);
    assert!(
        work.windows(2).all(|pair| pair[1] > pair[0]),
        "cumulative identical-row work grows at every prefix: {work:?}"
    );
    let increments: Vec<_> = work.windows(2).map(|pair| pair[1] - pair[0]).collect();
    assert!(
        increments.windows(2).all(|pair| pair[0] == pair[1]),
        "cumulative identical-row charges include the shared level cost once: {work:?}"
    );
    assert!(least.work > work[1], "cumulative multi-row work exceeds one-row prefix");
    let mut extended_work = Vec::new();
    for count in 0..=3 {
        let mut extended = fields.clone();
        extended.question.nodes.push(model::Node::Power(
            0,
            model::Fraction::new("1".into(), "1".into(), limits().arithmetic).unwrap(),
        ));
        extended.question.root = 1;
        if count < 3 {
            extended.tests.truncate(count);
            extended.rungs.as_mut().unwrap().rows.truncate(count);
            extended.ending = model::Ending::Operational(1);
            extended.polarity = None;
        }
        extended_work.push(least_budget(&extended).work);
    }
    assert!(
        extended_work
            .iter()
            .zip(&work)
            .all(|(extended, original)| extended > original),
        "cumulative question charges increase every prefix: original={work:?} extended={extended_work:?}"
    );
    let differences: Vec<_> = extended_work
        .iter()
        .zip(&work)
        .map(|(extended, original)| extended - original)
        .collect();
    assert!(
        differences.windows(2).all(|pair| pair[0] == pair[1]),
        "cumulative additional-question charge is shared once: {differences:?}"
    );
}
