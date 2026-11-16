use pn_host::publication::{comparison as shared, controller as codec};
use pn_records::{
    controller::{
        Delivery, Inputs,
        v2::{Attempt, Context, ResultKind, Stage},
    },
    numerics::{ComparisonLimits, ExactLimits, Floor, NumericContext},
    primitive::Range,
    solve::{Equality, Precision, Procedure},
};

fn limits() -> shared::Limits {
    shared::Limits {
        transport: pn_interchange::TransportLimits {
            input_bytes: 2_000_000,
            allocation_bytes: 8_000_000,
            items: 200_000,
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
fn text(value: &serde_json::Value) -> String {
    value.as_str().unwrap().into()
}
fn exact(value: &serde_json::Value) -> String {
    text(&value[0])
}
fn decimal(value: &serde_json::Value) -> u64 {
    value.as_str().unwrap().parse().unwrap()
}
fn procedure(value: &serde_json::Value) -> Procedure {
    let sequence = || {
        value[5][1]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| u32::try_from(decimal(v)).unwrap())
            .collect()
    };
    Procedure {
        edition: pn_records::DeclarationId {
            namespace: text(&value[0][0]),
            name: text(&value[0][1]),
            edition: decimal(&value[0][2]),
        },
        boundary: decimal(&value[1]),
        name: text(&value[2]),
        backend: text(&value[3]),
        primitives: std::collections::BTreeSet::new(),
        precision: match value[5][0].as_u64().unwrap() {
            0 => Precision::ExactRational,
            1 => Precision::BinaryBits(sequence()),
            2 => Precision::AbsoluteWidthBits(sequence()),
            _ => panic!("fixture precision code"),
        },
        equality: Equality::ExactRationalOnly,
        grid: vec![],
        margin: exact(&value[8]),
        maximum_work: decimal(&value[9]),
        maximum_solve_work: decimal(&value[10]),
        maximum_replay_work: decimal(&value[11]),
        maximum_iterations: decimal(&value[12]),
        endpoint_grid: exact(&value[13]),
        enclosure: None,
        fence: None,
    }
}
fn inputs(value: &serde_json::Value) -> Inputs {
    Inputs {
        width: text(&value["width"]),
        empty_live_domain: false,
        accepted_rung: "0".into(),
        cumulative_tilt: "1".into(),
        bleed_squared: "1/400".into(),
        previous: text(&value["previous"]),
        floor: if value["floor"] == 0 {
            Floor::RationalThreeThirtySevenths
        } else {
            Floor::RidgeImage
        },
        absolute_cap: text(&value["absolute_cap"]),
        relative_cap: text(&value["relative_cap"]),
        deadband: text(&value["deadband"]),
        bracket: Range {
            lower: "1/20".into(),
            upper: "3/4".into(),
        },
        stopping_width: "1/100".into(),
        maximum_steps: 10,
        maximum_work: 1_000_000,
        maximum_replay_work: 1_000_000,
        delivery: if value["delivery"] == "exact" {
            Delivery::ExactRational
        } else {
            Delivery::Grid {
                quantum: text(&value["quantum"]),
                maximum_error: text(&value["maximum_error"]),
            }
        },
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
    serde_json::from_str(include_str!("../data/controller-carriers.json")).unwrap()
}
fn shared_error(error: &shared::Error) -> String {
    match error {
        shared::Error::Projection(error) => format!("Projection::{error:?}").split([' ', '(']).next().unwrap().into(),
        shared::Error::Canonical(error) => format!("{error:?}").split([' ', '{']).next().unwrap().into(),
        other => format!("{other:?}").split([' ', '(']).next().unwrap().into(),
    }
}
fn error_name(error: &codec::Error) -> String {
    match error {
        codec::Error::Comparison(error) => shared_error(error),
        codec::Error::Record(pn_records::controller::v2::Error::Comparison(error)) => format!("Comparison::{error:?}"),
        codec::Error::Record(error) => format!("{error:?}"),
        codec::Error::Projection(error) => format!("Projection::{error:?}").split([' ', '(']).next().unwrap().into(),
        other => format!("{other:?}"),
    }
}
fn stage_code(stage: Stage) -> u64 {
    match stage {
        Stage::Floor => 0,
        Stage::InverseGain => 1,
        Stage::Deadband => 2,
        Stage::Direction => 3,
        Stage::AbsoluteCap => 4,
        Stage::RelativeCap => 5,
        Stage::Delivery => 6,
    }
}
fn assert_result(attempt: &Attempt, value: &serde_json::Value, name: &str) {
    let (code, stage) = match &attempt.result {
        ResultKind::Delivered => (0, None),
        ResultKind::Indecisive { stage, .. } => (1, Some(*stage)),
        ResultKind::Operational { stage, .. } => (2, Some(*stage)),
        ResultKind::Refused { stage, .. } => (3, Some(*stage)),
    };
    assert_eq!(code, value[8][0].as_u64().unwrap(), "{name}: result constructor meaning");
    if let Some(stage) = stage {
        assert_eq!(stage_code(stage), value[8][1][0].as_u64().unwrap(), "{name}: stage meaning");
    }
    assert_eq!(
        attempt.stopped_at.map(stage_code),
        value[2][0].as_u64(),
        "{name}: stopped-at meaning"
    );
}

/// Claim: Independent integer-generated controller fragments reach both explicit readers unsorted; supplied cases retain complete result constructors and stage meanings, round-trip their canonical bytes, or refuse their named first clause without claiming controller execution or enclosure soundness.
/// ´claim:host:controller-corpus-refuses-first-clause´
/// ´test:integration:controller-corpus´
#[test]
fn controller_corpus() {
    let data = corpus();
    let rows = data["cases"].as_array().unwrap();
    assert!(
        rows.windows(2)
            .any(|pair| pair[0]["case"].as_str() > pair[1]["case"].as_str()),
        "controller cases reach the codec unsorted"
    );
    let distinct: std::collections::BTreeSet<_> = rows.iter().map(|row| row["canonical"].as_str().unwrap()).collect();
    assert_eq!(
        distinct.len() as u64,
        data["distinct_byte_inputs"].as_u64().unwrap(),
        "distinct byte count"
    );
    let proof = super::comparison::defining_proof();
    for row in rows {
        let name = row["case"].as_str().unwrap();
        let raw = bytes(&row["canonical"]);
        let procedure = procedure(&row["procedure"]);
        let expected_procedure = self::procedure(&row["expected_procedure"]);
        let inputs = inputs(&row["inputs"]);
        let expected_inputs = self::inputs(&row["expected"]);
        let request = Context {
            procedure: &procedure,
            inputs: &inputs,
            index: usize::try_from(row["index"].as_u64().unwrap()).unwrap(),
            proof: if row["proof"] == "missing" { None } else { Some(&proof) },
        };
        let expected = Context {
            procedure: &expected_procedure,
            inputs: &expected_inputs,
            index: usize::try_from(row["expected_index"].as_u64().unwrap()).unwrap(),
            proof: if row["proof"] == "missing" { None } else { Some(&proof) },
        };
        let outcome = if row["edition"] == "attempt" {
            codec::decode_attempt(&raw, &request, &expected, &mut numeric(), &limits()).map(|value| {
                assert_eq!(
                    row["result"], "valid",
                    "{name}: first structural refusal: decoder accepted refused input"
                );
                assert_result(&value, &row["value"], name);
                codec::encode_attempt(&value, &request, &expected, &mut numeric(), &limits()).unwrap()
            })
        } else {
            codec::decode_record(&raw, &expected, &mut numeric(), &limits()).map(|value| {
                assert_eq!(
                    row["result"], "valid",
                    "{name}: first structural refusal: decoder accepted refused input"
                );
                for (attempt, raw) in value.attempts.iter().zip(row["value"][3].as_array().unwrap()) {
                    assert_result(attempt, raw, name);
                }
                codec::encode_record(&value, &expected, &mut numeric(), &limits()).unwrap()
            })
        };
        if row["result"] == "valid" {
            assert!(
                outcome.is_ok(),
                "{name}: expected valid, got {:?}",
                outcome.as_ref().err().map(error_name)
            );
            assert_eq!(outcome.unwrap(), raw, "{name}: canonical round trip");
        } else {
            assert_eq!(
                outcome.as_ref().err().map(error_name).as_deref(),
                row["result"].as_str(),
                "{name}: first structural refusal"
            );
        }
    }
}

/// Claim: A complete evaluated indecision retains both rational endpoints, their inclusion and its exact threshold through the explicitly selected controller fragment codec.
/// ´claim:host:controller-indecision-is-retained´
/// ´test:integration:controller-retained-evidence´
#[test]
fn controller_retained_evidence() {
    use pn_records::numerics::comparison::ResultKind as Comparison;
    let corpus = corpus();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == "floor-target-straddle")
        .unwrap();
    let procedure = procedure(&row["procedure"]);
    let inputs = inputs(&row["inputs"]);
    let context = Context {
        procedure: &procedure,
        inputs: &inputs,
        index: 0,
        proof: None,
    };
    let raw = bytes(&row["canonical"]);
    let attempt = codec::decode_attempt(&raw, &context, &context, &mut numeric(), &limits()).unwrap();
    assert_eq!(
        codec::encode_attempt(&attempt, &context, &context, &mut numeric(), &limits()).unwrap(),
        raw,
        "indecision complete enclosure and threshold remain encoded"
    );
    assert!(
        matches!(attempt.result, ResultKind::Indecisive { .. }),
        "indecisive constructor retained"
    );
    let ResultKind::Indecisive { comparison, .. } = &attempt.result else {
        unreachable!()
    };
    assert!(
        matches!(comparison.result, Comparison::Evaluated { .. }),
        "evaluated constructor retained"
    );
    let Comparison::Evaluated {
        enclosure,
        threshold,
        verdict,
        ..
    } = &comparison.result
    else {
        panic!("evaluated evidence retained")
    };
    assert_eq!(enclosure.lower.parts(), ("-23", "740"), "indecision lower endpoint retained");
    assert_eq!(enclosure.upper.parts(), ("7", "370"), "indecision upper endpoint retained");
    assert!(
        enclosure.lower_included && enclosure.upper_included,
        "indecision fences retained"
    );
    assert_eq!(threshold.parts(), ("0", "1"), "indecision exact threshold retained");
    assert_eq!(*verdict, 2, "indecision remains a mathematical verdict");
}

/// Claim: Controller validation retains prior arithmetic charges, shares one ledger across attempts, refuses below the least admitting work ceiling and checks the fragment byte ceiling at its boundary.
/// ´claim:host:controller-ceilings-are-cumulative´
/// ´test:integration:controller-ceilings´
#[test]
fn controller_ceilings() {
    use pn_epoch::publication::disclosures::{Rational, limits::Budget};
    use pn_records::controller::v2::{Error, Record};
    let corpus = corpus();
    let row = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case"] == "floor-target-straddle")
        .unwrap();
    let procedure = procedure(&row["procedure"]);
    let inputs = inputs(&row["inputs"]);
    let context = Context {
        procedure: &procedure,
        inputs: &inputs,
        index: 0,
        proof: None,
    };
    let raw = bytes(&row["canonical"]);
    let attempt = codec::decode_attempt(&raw, &context, &context, &mut numeric(), &limits()).unwrap();
    let mut second = attempt.clone();
    second.precision = 16;
    let record = Record {
        procedure: procedure.clone(),
        inputs: inputs.clone(),
        attempts: vec![attempt.clone(), second],
    };
    let run = |work, prior| {
        let mut declaration = limits().arithmetic;
        declaration.work = work;
        let mut budget = Budget::new(declaration).unwrap();
        if prior {
            Rational::parse("314159/271828", &mut budget).unwrap();
        }
        let initial = budget.usage().work;
        let result = record.validate(&procedure, &inputs, None, &mut budget);
        (result, initial, budget.usage().work)
    };
    let (result, _, work) = run(limits().arithmetic.work, false);
    assert!(result.is_ok(), "two complete attempts validate");
    let mut one = Budget::new(limits().arithmetic).unwrap();
    attempt.validate(&context, &context, &mut one).unwrap();
    assert!(work > one.usage().work, "second attempt consumes cumulative work");
    let (result, prior, total) = run(limits().arithmetic.work, true);
    assert!(result.is_ok(), "prior arithmetic permits complete record");
    assert!(prior > 0, "prior question charge is positive");
    assert_eq!(
        total,
        prior + work,
        "record cannot reset prior question or per-attempt ledger"
    );
    let mut low = 1;
    let mut high = limits().arithmetic.work;
    while low < high {
        let middle = low + (high - low) / 2;
        if run(middle, false).0.is_ok() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert_eq!(
        run(low - 1, false).0,
        Err(Error::Comparison(pn_records::numerics::comparison::Error::Resource)),
        "least record budget minus one refuses"
    );
    assert!(run(low, false).0.is_ok(), "least record budget admits");
    let mut boundary = limits();
    boundary.transport.input_bytes = raw.len();
    assert!(
        codec::decode_attempt(&raw, &context, &context, &mut numeric(), &boundary).is_ok(),
        "controller exact byte ceiling admits"
    );
    boundary.transport.input_bytes -= 1;
    assert!(
        matches!(
            codec::decode_attempt(&raw, &context, &context, &mut numeric(), &boundary),
            Err(codec::Error::Comparison(shared::Error::Resource))
        ),
        "controller one-past byte ceiling refuses"
    );
}
