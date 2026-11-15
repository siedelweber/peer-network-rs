use pn_host::publication::comparison as codec;
use pn_records::{
    binary64::Fraction,
    numerics::{
        ComparisonLimits, ExactLimits, NumericContext, NumericError,
        comparison::{DefiningProof, Expected, Question},
    },
    ridge::{ChargeEvidence, ChargeVerifier, Definition, Wall},
};

fn limits() -> codec::Limits {
    codec::Limits {
        transport: pn_interchange::TransportLimits {
            input_bytes: 1_000_000,
            allocation_bytes: 4_000_000,
            items: 100_000,
            depth: 64,
            nesting: 64,
            work: 20_000_000,
        },
        arithmetic: ExactLimits {
            work: 20_000_000,
            literal_bytes: 4096,
            ..ExactLimits::default()
        },
    }
}
fn numeric() -> NumericContext {
    NumericContext::new(limits().arithmetic, ComparisonLimits::new(1, 20_000_000)).unwrap()
}
fn fraction(value: &serde_json::Value) -> Fraction {
    Fraction::new(
        value[0].as_str().unwrap().into(),
        value[1].as_str().unwrap().into(),
        limits().arithmetic,
    )
    .unwrap()
}
fn definition() -> Definition {
    Definition {
        schema: "clean-elasticity-ridge-v1".into(),
        inverse_temperature: "2*ln(2)".into(),
        bleed_squared: "0".into(),
        core_power: "1".into(),
    }
}
fn operand(value: &serde_json::Value) -> Wall {
    match value.as_str().unwrap() {
        "ridge" => Wall::DefiningRidge(definition()),
        "foreign-ridge" => {
            let mut d = definition();
            d.core_power = "2".into();
            Wall::DefiningRidge(d)
        }
        text => Wall::Rational(text.into()),
    }
}
fn question(value: &serde_json::Value) -> Question {
    Question {
        left: operand(&value[0]),
        right: operand(&value[1]),
    }
}
fn expected(value: &serde_json::Value) -> Expected {
    Expected {
        question: question(&value["question"]),
        reduction: value["reduction"].as_u64().unwrap(),
        predicate: value["predicate"].as_u64().unwrap(),
        threshold: fraction(&value["threshold"]),
    }
}
fn bytes(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../data/comparison-carriers.json")).unwrap()
}

#[derive(Debug)]
struct VerifiedFixture(ChargeEvidence);
impl ChargeVerifier for VerifiedFixture {
    fn replay(&self, evidence: &ChargeEvidence) -> Result<(), NumericError> {
        if evidence == &self.0 {
            Ok(())
        } else {
            Err(NumericError::RidgeEvidence)
        }
    }
}

#[derive(Debug)]
struct CompletenessProbe<'a>(&'a ChargeEvidence);
impl ChargeVerifier for CompletenessProbe<'_> {
    fn replay(&self, evidence: &ChargeEvidence) -> Result<(), NumericError> {
        // Only the negative completeness fixture uses this deliberately permissive
        // replay premise; the carrier must reject its absent image independently.
        if evidence == self.0 {
            Ok(())
        } else {
            Err(NumericError::RidgeEvidence)
        }
    }
}

fn fixture() -> &'static VerifiedFixture {
    static FIXTURE: std::sync::OnceLock<VerifiedFixture> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (disclosure, check) = pn_epoch::test_support::ridge_disclosures();
        let evidence = disclosure.frames[0].price.ridge.as_ref().unwrap().as_ref().clone();
        pn_epoch::publication::disclosures::restore(disclosure, &check).unwrap();
        // Only this exact proof was independently restored by the existing kernel.
        // This finite fixture is not a general implementation of the replay obligation.
        VerifiedFixture(evidence)
    })
}

fn defining_proof() -> DefiningProof<'static> {
    let fixture = fixture();
    DefiningProof {
        evidence: &fixture.0,
        verifier: fixture,
    }
}

fn result_name(error: &codec::Error) -> String {
    match error {
        codec::Error::Record(value) => format!("{value:?}"),
        codec::Error::Projection(value) => format!("Projection::{value:?}").split([' ', '(']).next().unwrap().into(),
        codec::Error::Canonical(value) => format!("{value:?}").split([' ', '{']).next().unwrap().into(),
        value => format!("{value:?}").split([' ', '(']).next().unwrap().into(),
    }
}

/// Claim: Independently generated comparison fragments reach both explicit second-edition readers unsorted; supplied cases retain complete evaluated verdicts, exact results and operational causes or refuse their named first clause, with positive defining proofs bound to an independently restored finite fixture and a negative permissive replay premise isolating completeness.
/// ´claim:host:comparison-corpus-refuses-first-clause´
/// ´test:integration:comparison-corpus´
#[test]
fn comparison_corpus() {
    let data = corpus();
    let fixture = fixture();
    for row in data["cases"].as_array().unwrap() {
        let name = row["case"].as_str().unwrap();
        let question = question(&row["question"]);
        let expected = expected(&row["expected"]);
        let mut evidence = fixture.0.clone();
        match row["proof"].as_str().unwrap() {
            "foreign" => evidence.input.definition.core_power = "2".into(),
            "incomplete" => evidence.record.image = None,
            "invalid" => evidence.record.work = evidence.record.work.saturating_add(1),
            _ => {}
        }
        let completeness = CompletenessProbe(&evidence);
        let verifier: &dyn ChargeVerifier = if row["proof"] == "incomplete" {
            &completeness
        } else {
            fixture
        };
        let proof = DefiningProof {
            evidence: &evidence,
            verifier,
        };
        let request = codec::Request {
            question: &question,
            expected: &expected,
            proof: if row["proof"] == "missing" { None } else { Some(&proof) },
        };
        let input = bytes(&row["canonical"]);
        let floor = if matches!(expected.question.right, Wall::DefiningRidge(_)) {
            pn_records::numerics::Floor::RidgeImage
        } else {
            pn_records::numerics::Floor::RationalThreeThirtySevenths
        };
        let mut context = numeric();
        let result = if row["edition"] == "floor" {
            codec::decode_floor(&input, &request, &mut context, &limits())
                .and_then(|value| codec::encode_floor(&value, &request, &mut numeric(), &limits()))
        } else {
            codec::decode_ridge(&input, floor, &request, &mut context, &limits())
                .and_then(|value| codec::encode_ridge(&value, floor, &request, &mut numeric(), &limits()))
        };
        if row["result"] == "valid" {
            assert!(result.is_ok(), "{name}: valid comparison fragment: {result:?}");
            assert_eq!(result.unwrap(), input, "{name}: complete fragment round trip");
        } else {
            let actual = result.as_ref().err().map_or_else(|| "accepted".into(), result_name);
            assert_eq!(actual, row["result"].as_str().unwrap(), "{name}: first comparison refusal");
        }
    }
}

fn simple() -> (pn_records::numerics::comparison::FloorComparisonV2, Question, Expected) {
    let corpus = corpus();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == "evaluated-0-1-3")
        .unwrap();
    let question = question(&row["question"]);
    let expected = expected(&row["expected"]);
    let request = codec::Request {
        question: &question,
        expected: &expected,
        proof: Some(&defining_proof()),
    };
    let value = codec::decode_floor(&bytes(&row["canonical"]), &request, &mut numeric(), &limits()).unwrap();
    (value, question, expected)
}

fn validate(
    value: &pn_records::numerics::comparison::FloorComparisonV2,
    question: &Question,
    expected: &Expected,
    work: u64,
) -> Result<u64, pn_records::numerics::comparison::Error> {
    let mut limits = limits().arithmetic;
    limits.work = work;
    let mut budget = pn_epoch::publication::disclosures::limits::Budget::new(limits).unwrap();
    value.validate(question, expected, Some(&defining_proof()), &mut budget)?;
    Ok(budget.usage().work)
}

/// Claim: The comparison binding control substitutes both original operands, the declared reduction, predicate and exact threshold; an alternative consistent interval remains a claim rather than an origin check, and a complete INDECISIVE enclosure round-trips unchanged.
/// ´claim:host:comparison-binding-keeps-enclosure-claim´
/// ´test:integration:comparison-binding´
#[test]
fn comparison_binding() {
    use pn_records::numerics::comparison::{Error, ResultKind};
    let (value, question, expected) = simple();
    let check = |v: &pn_records::numerics::comparison::FloorComparisonV2, q: &Question, e: &Expected| {
        validate(v, q, e, limits().arithmetic.work).map(|_| ())
    };
    let mut changed = question.clone();
    changed.left = Wall::Rational("3".into());
    assert_eq!(
        check(&value, &changed, &expected),
        Err(Error::QuestionLeft),
        "original left operand binding"
    );
    let mut changed = question.clone();
    changed.right = Wall::Rational("3".into());
    assert_eq!(
        check(&value, &changed, &expected),
        Err(Error::QuestionRight),
        "original right operand binding"
    );
    let mut changed = value.clone();
    if let ResultKind::Evaluated { reduction, .. } = &mut changed.result {
        *reduction = 1;
    }
    assert_eq!(
        check(&changed, &question, &expected),
        Err(Error::ExpectedReduction),
        "declared quantity binding"
    );
    let mut changed = value.clone();
    if let ResultKind::Evaluated { predicate, .. } = &mut changed.result {
        *predicate = 2;
    }
    assert_eq!(
        check(&changed, &question, &expected),
        Err(Error::ExpectedPredicate),
        "predicate binding"
    );
    let mut changed = expected.clone();
    changed.threshold = fraction(&serde_json::json!(["1", "1"]));
    assert_eq!(
        check(&value, &question, &changed),
        Err(Error::ExpectedThreshold),
        "exact expected threshold binding"
    );
    let mut changed = value.clone();
    if let ResultKind::Evaluated { enclosure, .. } = &mut changed.result {
        enclosure.lower = fraction(&serde_json::json!(["-2", "1"]));
        enclosure.upper = fraction(&serde_json::json!(["2", "1"]));
    }
    assert_eq!(
        check(&changed, &question, &expected),
        Ok(()),
        "interval origin is not a carrier check"
    );
    let request = codec::Request {
        question: &question,
        expected: &expected,
        proof: Some(&defining_proof()),
    };
    let bytes = codec::encode_floor(&changed, &request, &mut numeric(), &limits()).unwrap();
    let decoded = codec::decode_floor(&bytes, &request, &mut numeric(), &limits());
    assert!(
        decoded.is_ok(),
        "INDECISIVE keeps a consistent complete enclosure and threshold: {decoded:?}"
    );
    assert_eq!(
        decoded.unwrap(),
        changed,
        "INDECISIVE keeps its complete enclosure and threshold"
    );
}

/// Claim: A comparison consumes one cumulative arithmetic ledger, retains prior question work, refuses one below its least admitting work ceiling and refuses a second comparison when only two complete first-call costs minus one are available; repeated ridge query projections add equal work to the nested comparison, and the byte reader refuses one below the complete fragment length.
/// ´claim:host:comparison-ceilings-are-cumulative´
/// ´test:integration:comparison-ceilings´
#[test]
fn comparison_ceilings() {
    use pn_epoch::publication::disclosures::{Rational, limits::Budget};
    use pn_records::numerics::comparison::Error;
    let (value, question, expected) = simple();
    let mut lo = 1;
    let mut hi = limits().arithmetic.work;
    while lo < hi {
        let middle = lo + (hi - lo) / 2;
        if validate(&value, &question, &expected, middle).is_ok() {
            hi = middle;
        } else {
            lo = middle + 1;
        }
    }
    let first = validate(&value, &question, &expected, lo).unwrap();
    assert!(first > 0, "comparison arithmetic is charged");
    assert_eq!(
        validate(&value, &question, &expected, lo - 1),
        Err(Error::Resource),
        "least comparison work minus one refuses"
    );
    let mut declaration = limits().arithmetic;
    declaration.work = 2 * first - 1;
    let mut budget = Budget::new(declaration).unwrap();
    assert!(
        value
            .validate(&question, &expected, Some(&defining_proof()), &mut budget)
            .is_ok(),
        "one complete comparison fits before the second-call boundary"
    );
    assert_eq!(
        value.validate(&question, &expected, Some(&defining_proof()), &mut budget),
        Err(Error::Resource),
        "second comparison cannot reset the cumulative ledger"
    );
    let mut budget = Budget::new(limits().arithmetic).unwrap();
    Rational::parse("314159/271828", &mut budget).unwrap();
    let before = budget.usage().work;
    value
        .validate(&question, &expected, Some(&defining_proof()), &mut budget)
        .unwrap();
    assert_eq!(
        budget.usage().work,
        before + first,
        "prior question work is retained through every comparison level"
    );
    let request = codec::Request {
        question: &question,
        expected: &expected,
        proof: Some(&defining_proof()),
    };
    let bytes = codec::encode_floor(&value, &request, &mut numeric(), &limits()).unwrap();
    let mut limit = limits();
    limit.transport.input_bytes = bytes.len();
    assert!(
        codec::decode_floor(&bytes, &request, &mut numeric(), &limit).is_ok(),
        "fragment exactly at byte ceiling"
    );
    limit.transport.input_bytes -= 1;
    assert!(
        matches!(
            codec::decode_floor(&bytes, &request, &mut numeric(), &limit),
            Err(codec::Error::Resource)
        ),
        "fragment one past byte ceiling refuses"
    );
    comparison_projection_budget();
}

fn comparison_projection_budget() {
    use pn_records::numerics::{Floor, comparison::Error};
    let data = corpus();
    let row = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == "ridge-query-pair")
        .unwrap();
    let question = question(&row["question"]);
    let expected = expected(&row["expected"]);
    let request = codec::Request {
        question: &question,
        expected: &expected,
        proof: Some(&defining_proof()),
    };
    let mut record = codec::decode_ridge(
        &bytes(&row["canonical"]),
        Floor::RidgeImage,
        &request,
        &mut numeric(),
        &limits(),
    )
    .unwrap();
    let mut costs = Vec::new();
    for count in (0..=2).rev() {
        record.queries.truncate(count);
        let bytes = codec::encode_ridge(&record, Floor::RidgeImage, &request, &mut numeric(), &limits()).unwrap();
        let read = |work| {
            let mut declaration = limits();
            declaration.arithmetic.work = work;
            codec::decode_ridge(&bytes, Floor::RidgeImage, &request, &mut numeric(), &declaration)
        };
        let mut lower = 1;
        let mut upper = limits().arithmetic.work;
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            if read(middle).is_ok() {
                upper = middle;
            } else {
                lower = middle + 1;
            }
        }
        assert!(read(lower).is_ok(), "ridge projection least arithmetic ceiling admits");
        assert!(
            matches!(read(lower - 1), Err(codec::Error::Record(Error::Resource))),
            "ridge projection and nested comparison share the last arithmetic charge"
        );
        costs.push(lower);
    }
    assert!(
        costs[0] > costs[1] && costs[1] > costs[2],
        "each retained query adds cumulative reconstruction work"
    );
    assert_eq!(
        costs[0] - costs[1],
        costs[1] - costs[2],
        "identical query projections add equal work before comparison"
    );
}
