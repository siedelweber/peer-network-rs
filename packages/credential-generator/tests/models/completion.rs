#[derive(Clone, Copy)]
struct ResultRecord {
    invocation: u64,
    ended: bool,
    success: bool,
    status: u8,
}

#[derive(Clone, Copy)]
struct Stream {
    length: usize,
    ended: bool,
    sealed_length: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PremiseMember {
    Declared,
    Missing,
}

#[derive(Clone, Copy)]
struct Premise {
    fixed_name: PremiseMember,
    content_independent: PremiseMember,
    non_decreasing: PremiseMember,
    strict_below: PremiseMember,
    strict_above: PremiseMember,
}

impl Premise {
    fn holds(self) -> bool {
        [
            self.fixed_name,
            self.content_independent,
            self.non_decreasing,
            self.strict_below,
            self.strict_above,
        ]
        .into_iter()
        .all(|member| member == PremiseMember::Declared)
    }
}

#[derive(Clone, Copy)]
struct Calibration {
    premise: Premise,
    measure: u64,
    format: u64,
    password_length: usize,
    verifier_length: usize,
}

fn authorizes(
    invocation: u64,
    result: Option<ResultRecord>,
    streams: [Stream; 2],
    calibration: Calibration,
    current: (u64, u64),
) -> bool {
    result.is_some_and(|r| r.invocation == invocation && r.ended && r.success && r.status == 0)
        && calibration.premise.holds()
        && current == (calibration.measure, calibration.format)
        && streams[0].length == 64
        && streams[1].length == 135
        && streams.iter().all(|s| s.ended)
        && streams[0].sealed_length == calibration.password_length
        && streams[1].sealed_length == calibration.verifier_length
}

/// A matching ended successful supervisor result and two exact ended streams
/// are necessary together; full streams alone cannot authorize publication.
/// ´claim:generator:completion-model-requires-the-matching-supervisor-result´
/// ´test:integration:completion-result´
#[test]
fn completion_result() {
    let good = ResultRecord {
        invocation: 3,
        ended: true,
        success: true,
        status: 0,
    };
    let streams = [
        Stream {
            length: 64,
            ended: true,
            sealed_length: 80,
        },
        Stream {
            length: 135,
            ended: true,
            sealed_length: 160,
        },
    ];
    let calibration = Calibration {
        premise: premise(),
        measure: 5,
        format: 7,
        password_length: 80,
        verifier_length: 160,
    };
    assert!(
        authorizes(3, Some(good), streams, calibration, (5, 7)),
        "complete matching model case"
    );
    for result in [
        None,
        Some(ResultRecord { invocation: 4, ..good }),
        Some(ResultRecord { ended: false, ..good }),
        Some(ResultRecord { success: false, ..good }),
        Some(ResultRecord { status: 1, ..good }),
    ] {
        assert!(
            !authorizes(3, result, streams, calibration, (5, 7)),
            "reader completion never replaces the matching supervisor result"
        );
    }
    for index in 0..2 {
        for length in [0, streams[index].length - 1, streams[index].length + 1] {
            let mut changed = streams;
            changed[index].length = length;
            assert!(
                !authorizes(3, Some(good), changed, calibration, (5, 7)),
                "partial or additional stream refuses"
            );
        }
        let mut changed = streams;
        changed[index].ended = false;
        assert!(
            !authorizes(3, Some(good), changed, calibration, (5, 7)),
            "missing stream end refuses"
        );
    }
}

/// The length model refuses an invalid calibration premise, any changed measure
/// or sealing format without recalibration, and either sealed-length mismatch.
/// ´claim:generator:stream-model-keeps-the-complete-calibration-premise´
/// ´test:integration:calibration´
#[test]
fn calibration() {
    let result = Some(ResultRecord {
        invocation: 3,
        ended: true,
        success: true,
        status: 0,
    });
    let streams = [
        Stream {
            length: 64,
            ended: true,
            sealed_length: 80,
        },
        Stream {
            length: 135,
            ended: true,
            sealed_length: 160,
        },
    ];
    let calibration = Calibration {
        premise: premise(),
        measure: 5,
        format: 7,
        password_length: 80,
        verifier_length: 160,
    };
    for premise in [
        Premise {
            fixed_name: PremiseMember::Missing,
            ..premise()
        },
        Premise {
            content_independent: PremiseMember::Missing,
            ..premise()
        },
        Premise {
            non_decreasing: PremiseMember::Missing,
            ..premise()
        },
        Premise {
            strict_below: PremiseMember::Missing,
            ..premise()
        },
        Premise {
            strict_above: PremiseMember::Missing,
            ..premise()
        },
    ] {
        assert!(
            !authorizes(3, result, streams, Calibration { premise, ..calibration }, (5, 7)),
            "each member of the declared calibration premise is required"
        );
    }
    for current in [(6, 7), (5, 8)] {
        assert!(
            !authorizes(3, result, streams, calibration, current),
            "changed measure or format requires recalibration"
        );
    }
    for index in 0..2 {
        let mut changed = streams;
        changed[index].sealed_length += 1;
        assert!(
            !authorizes(3, result, changed, calibration, (5, 7)),
            "sealed length mismatch refuses"
        );
    }
}

fn premise() -> Premise {
    Premise {
        fixed_name: PremiseMember::Declared,
        content_independent: PremiseMember::Declared,
        non_decreasing: PremiseMember::Declared,
        strict_below: PremiseMember::Declared,
        strict_above: PremiseMember::Declared,
    }
}
