//! Fixed typed operands for the pure successor marker admission.
//! (´[ROOT-verif:identity:marker-controls]´)

use pn_records::successor_marker::*;

const Z: [u8; 32] = [0; 32];
const R: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

fn view(version: [u64; 3], value: [u8; 32]) -> DecodedMarker {
    DecodedMarker::from_decoded_parts(version, value).unwrap()
}

fn decoded(value: [u8; 32]) -> MarkerRead {
    MarkerRead::Decoded(view([1, 0, 0], value), MarkerAcceptance::Strict)
}

fn origin() -> MarkerFacts {
    MarkerFacts {
        marker_movement: MarkerMovementContext::Established,
        place: MarkerPlace::AuthenticatedOrigin,
        movement: MarkerMovement::Satisfied,
        preceding_root: PrecedingRoot::Unknown,
    }
}

fn following() -> MarkerFacts {
    MarkerFacts {
        marker_movement: MarkerMovementContext::Established,
        place: MarkerPlace::AuthenticatedFollowing,
        movement: MarkerMovement::Satisfied,
        preceding_root: PrecedingRoot::Known(R),
    }
}

/// Claim: First and following constructors enforce the major-one zero placement policy on supplied intent.
/// ´claim:identity:marker-construction´
/// ´test:integration:marker-construction´
#[test]
fn marker_construction() {
    // Claim: marker-construction. Supplied intent alone fixes the constructed version and zero policy.
    let first = first_marker(0);
    assert_eq!(first.version(), [1, 0, 0]);
    assert_eq!(first.value(), Z);
    let last_patch = first_marker(u64::MAX);
    assert_eq!(last_patch.version(), [1, 0, u64::MAX]);
    assert_eq!(last_patch.value(), Z);
    let following = following_marker(R, 24).unwrap();
    assert_eq!(following.version(), [1, 0, 24]);
    assert_eq!(following.value(), R);
    assert_eq!(following_marker(Z, 0), Err(MarkerConstructionError::ZeroFollowingRoot));
    assert_eq!(
        DecodedMarker::from_decoded_parts([0, 0, 0], Z),
        Err(MarkerDecodedError::WrongMajor)
    );
    assert_eq!(
        DecodedMarker::from_decoded_parts([2, 0, 0], R),
        Err(MarkerDecodedError::WrongMajor)
    );
    let decoded = view([1, 1, 24], R);
    assert_eq!(decoded.version(), [1, 1, 24]);
    assert_eq!(decoded.value(), R);
}

/// Claim: Payload equality retains the complete unsigned version and every value byte.
/// ´claim:identity:marker-payload-equality´
/// ´test:integration:marker-payload-equality´
#[test]
fn marker_payload_equality() {
    // Claim: marker-payload-equality. The version and every value byte participate.
    let first = first_marker(0);
    assert!(same_marker(first, first));
    assert!(!same_marker(first, following_marker(R, 0).unwrap()));
    assert!(!same_marker(first, first_marker(1)));
}

/// Claim: Comparison with a supplied root is exact word equality without byte-order conversion.
/// ´claim:identity:marker-root-comparison´
/// ´test:integration:marker-root-comparison´
#[test]
fn marker_root_comparison() {
    // Claim: marker-root-comparison. No root byte-order conversion is admitted.
    let view = view([1, 0, 0], R);
    assert_eq!(compare_marker_root(view, R), MarkerRootComparison::Equal);
    assert_eq!(compare_marker_root(view, Z), MarkerRootComparison::Different);
    let mut reversed = R;
    reversed.reverse();
    assert_eq!(compare_marker_root(view, reversed), MarkerRootComparison::Different);
}

/// Claim: Every established and combined error wins over missing evidence in the declared flag order.
/// ´claim:identity:marker-error-precedence´
/// ´test:integration:marker-error-precedence´
#[test]
fn marker_error_precedence() {
    // Claim: marker-error-precedence. Expected flag records are literal, not assessment output.
    let mut breached = following();
    breached.movement = MarkerMovement::Breached;
    assert_eq!(
        assess_marker(decoded(R), breached),
        Ok(MarkerJudgement::Error(MarkerErrors {
            movement_breach: true,
            ..MarkerErrors::default()
        }))
    );
    assert_eq!(
        assess_marker(decoded(R), origin()),
        Ok(MarkerJudgement::Error(MarkerErrors {
            origin_nonzero: true,
            ..MarkerErrors::default()
        }))
    );
    let mut no_root = following();
    no_root.preceding_root = PrecedingRoot::Unknown;
    assert_eq!(
        assess_marker(decoded(Z), no_root),
        Ok(MarkerJudgement::Error(MarkerErrors {
            following_zero: true,
            ..MarkerErrors::default()
        }))
    );
    let mut wrong_root = following();
    wrong_root.preceding_root = PrecedingRoot::Known(Z);
    assert_eq!(
        assess_marker(decoded(R), wrong_root),
        Ok(MarkerJudgement::Error(MarkerErrors {
            root_mismatch: true,
            ..MarkerErrors::default()
        }))
    );
    let mut combined = no_root;
    combined.movement = MarkerMovement::Breached;
    assert_eq!(
        assess_marker(decoded(Z), combined),
        Ok(MarkerJudgement::Error(MarkerErrors {
            movement_breach: true,
            following_zero: true,
            ..MarkerErrors::default()
        }))
    );
    for reason in [MarkerVersionRejection::UnheldMajor, MarkerVersionRejection::UnassignedMinor] {
        let mut facts = following();
        facts.place = MarkerPlace::Unknown;
        facts.movement = MarkerMovement::Unknown;
        facts.preceding_root = PrecedingRoot::Unknown;
        let expected = MarkerErrors {
            unheld_major: reason == MarkerVersionRejection::UnheldMajor,
            unassigned_minor: reason == MarkerVersionRejection::UnassignedMinor,
            ..MarkerErrors::default()
        };
        assert_eq!(
            assess_marker(MarkerRead::VersionRejected(reason, [2, 0, 0]), facts),
            Ok(MarkerJudgement::Error(expected))
        );
    }
    let mut root_missing = following();
    root_missing.movement = MarkerMovement::Breached;
    root_missing.preceding_root = PrecedingRoot::Unknown;
    let breach = Ok(MarkerJudgement::Error(MarkerErrors {
        movement_breach: true,
        ..MarkerErrors::default()
    }));
    assert_eq!(assess_marker(decoded(R), root_missing), breach);
    let usage = MarkerReadUsage {
        received_bytes: 81,
        declared_input_bytes: 51,
        allocation_calls: 0,
        allocation_bytes: 0,
    };
    assert_eq!(
        assess_marker(
            MarkerRead::UnavailableBudget(MarkerReadBudgetReason::InputBytes, usage),
            root_missing
        ),
        breach
    );
    assert_eq!(
        assess_marker(
            MarkerRead::UnsupportedMeaning([1, 0, 0], MarkerAcceptance::Strict),
            root_missing
        ),
        breach
    );
}

/// Claim: Missing context, place, movement and root, plus unsupported interpretation, retain their named inability without inferring validity.
/// ´claim:identity:marker-unavailable´
/// ´test:integration:marker-unavailable´
#[test]
fn marker_unavailable() {
    // Claim: marker-unavailable. Each expected reason is supplied independently.
    assert_eq!(assess_marker(decoded(Z), origin()), Ok(MarkerJudgement::Valid));
    assert_eq!(assess_marker(decoded(R), following()), Ok(MarkerJudgement::Valid));
    let mut facts = following();
    facts.marker_movement = MarkerMovementContext::Unknown;
    assert_eq!(
        assess_marker(
            MarkerRead::VersionRejected(MarkerVersionRejection::UnheldMajor, [2, 0, 0]),
            facts
        ),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::MarkerContext))
    );
    facts = following();
    facts.place = MarkerPlace::Unknown;
    assert_eq!(
        assess_marker(decoded(Z), facts),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Facts(MarkerMissingFacts {
            place: true,
            ..MarkerMissingFacts::default()
        })))
    );
    facts = following();
    facts.movement = MarkerMovement::Unknown;
    assert_eq!(
        assess_marker(decoded(R), facts),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Facts(MarkerMissingFacts {
            movement: true,
            ..MarkerMissingFacts::default()
        })))
    );
    facts = following();
    facts.preceding_root = PrecedingRoot::Unknown;
    assert_eq!(
        assess_marker(decoded(R), facts),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Facts(MarkerMissingFacts {
            preceding_root: true,
            ..MarkerMissingFacts::default()
        })))
    );
    facts = following();
    facts.place = MarkerPlace::Unknown;
    facts.movement = MarkerMovement::Unknown;
    assert_eq!(
        assess_marker(decoded(R), facts),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Facts(MarkerMissingFacts {
            place: true,
            movement: true,
            preceding_root: false,
        })))
    );
    facts = following();
    facts.movement = MarkerMovement::Unknown;
    facts.preceding_root = PrecedingRoot::Unknown;
    assert_eq!(
        assess_marker(decoded(R), facts),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Facts(MarkerMissingFacts {
            place: false,
            movement: true,
            preceding_root: true,
        })))
    );
    assert_eq!(
        assess_marker(
            MarkerRead::UnsupportedMeaning([2, 0, 0], MarkerAcceptance::Strict),
            following()
        ),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::Interpretation))
    );
    let usage = MarkerReadUsage {
        received_bytes: 81,
        declared_input_bytes: 51,
        allocation_calls: 0,
        allocation_bytes: 0,
    };
    assert_eq!(
        assess_marker(
            MarkerRead::UnavailableBudget(MarkerReadBudgetReason::InputBytes, usage),
            following()
        ),
        Ok(MarkerJudgement::Unavailable(MarkerMissing::ReadBudget(
            MarkerReadBudgetReason::InputBytes,
            usage
        )))
    );
    assert_eq!(
        assess_marker(
            MarkerRead::Decoded(view([1, 1, 24], R), MarkerAcceptance::Tolerant),
            following()
        ),
        Ok(MarkerJudgement::Valid)
    );
}

/// Claim: Otherwise invalid payloads stay outside lineage verdicts unless an independent error is established.
/// ´claim:identity:marker-policy-boundary´
/// ´test:integration:marker-policy-boundary´
#[test]
fn marker_policy_boundary() {
    // Claim: marker-policy-boundary. Invalidity cannot become a lineage verdict by default.
    assert_eq!(
        assess_marker(MarkerRead::Invalid(MarkerInvalidReason::Theory), following()),
        Err(MarkerBoundary::UnclassifiedPayload(MarkerUnclassifiedPayload::Invalid(
            MarkerInvalidReason::Theory
        )))
    );
    assert_eq!(
        assess_marker(MarkerRead::NotMarker, following()),
        Err(MarkerBoundary::UnclassifiedPayload(MarkerUnclassifiedPayload::NotMarker))
    );
    let mut breached = following();
    breached.movement = MarkerMovement::Breached;
    assert_eq!(
        assess_marker(MarkerRead::Invalid(MarkerInvalidReason::Theory), breached),
        Ok(MarkerJudgement::Error(MarkerErrors {
            movement_breach: true,
            ..MarkerErrors::default()
        }))
    );
    let mut unknown = following();
    unknown.movement = MarkerMovement::Unknown;
    assert_eq!(
        assess_marker(MarkerRead::Invalid(MarkerInvalidReason::Theory), unknown),
        Err(MarkerBoundary::UnclassifiedPayload(MarkerUnclassifiedPayload::Invalid(
            MarkerInvalidReason::Theory
        )))
    );
}

/// Claim: Supported major one fixes the successor standard coordinate across minor and patch neighbours.
/// ´claim:identity:marker-standard-coordinate´
/// ´test:integration:marker-standard-coordinate´
#[test]
fn marker_standard_coordinate() {
    // Claim: marker-standard-coordinate. Minor and patch do not change the successor coordinate.
    for stamp in [[1, 0, 0], [1, 0, 1], [1, 0, 24], [1, 0, u64::MAX], [1, 1, 24]] {
        assert_eq!(
            marker_standard(view(stamp, R)),
            MarkerStandard {
                namespace: "o.pn.t.m",
                major: 1
            }
        );
    }
}
