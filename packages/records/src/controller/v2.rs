//! Controller comparison context and explicitly selected second-edition carriers.
//! (´[ROOT-dec:design:comparison-verdict-record]´)

use super::{Delivery, Inputs};
use crate::{
    numerics::{
        Floor,
        comparison::{ComparisonRecordV2, DefiningProof, Expected, FloorComparisonV2, Question, ResultKind as Comparison},
    },
    primitive::Range,
    ridge::{Definition, Wall},
    solve::{Precision, Procedure},
    wall::Record as InverseRecord,
};
use nrz_cas::{Rational, limits::Budget};

/// The second edition distinguishes the three step-cap questions.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Floor,
    InverseGain,
    Deadband,
    Direction,
    AbsoluteCap,
    RelativeCap,
    Delivery,
}

/// A prefix of decided comparisons, with ranges bound to the recorded decision.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branches {
    pub zero_width: bool,
    pub floor: Option<FloorComparisonV2>,
    pub deadband: Option<FloorComparisonV2>,
    pub absolute_cap: Option<FloorComparisonV2>,
    pub relative_cap: Option<FloorComparisonV2>,
    pub direction: Option<FloorComparisonV2>,
    pub proposal: Range,
    pub ideal: Option<Range>,
}

/// Disjoint results retain a complete comparison or an operational cause.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultKind {
    /// All required branch decisions accompany a delivered value.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Delivered,
    /// An evaluated straddle retains its enclosure and exact threshold.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Indecisive { stage: Stage, comparison: FloorComparisonV2 },
    /// No mathematical verdict is manufactured for an operational stop.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Operational { stage: Stage, cause: u64 },
    /// A complete failing comparison certifies a representation refusal.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Refused { stage: Stage, comparison: FloorComparisonV2 },
}

/// One explicitly selected attempt; no first-edition value is reinterpreted.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub precision: u32,
    pub stopped_at: Option<Stage>,
    pub inverse: Option<InverseRecord>,
    pub floor_checks: Vec<ComparisonRecordV2>,
    pub branches: Option<Branches>,
    pub delivered: Option<String>,
    pub delivery_error: Option<Range>,
    pub result: ResultKind,
}

/// An ordered nonempty attempt sequence with no duplicate summary verdict.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub procedure: Procedure,
    pub inputs: Inputs,
    pub attempts: Vec<Attempt>,
}

/// Independently supplied context and optional defining-ridge proof.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Debug)]
pub struct Context<'a> {
    pub procedure: &'a Procedure,
    pub inputs: &'a Inputs,
    pub index: usize,
    pub proof: Option<&'a DefiningProof<'a>>,
}

/// A structural refusal, never an operational cause or a mathematical verdict.
/// (´[ROOT-dec:design:comparison-verdict-record]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The procedure differs from the independent declaration.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Procedure,
    /// Original input operands differ from the independent declaration.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Inputs,
    /// The declared precision is not an absolute-width sequence.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    PrecisionKind,
    /// No declared precision exists at this attempt index.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    AttemptIndex,
    /// The attempt precision differs from its declared entry.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Precision,
    /// Bounded exact arithmetic refused its supplied ceiling.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Resource,
    /// An exact contextual literal cannot be parsed.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Number,
    /// The contextual width is negative.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Width,
    /// The previous wall is not positive.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Previous,
    /// The grid declaration cannot define bounded nearest-point selection.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveryDeclaration,
    /// A retained floor check has a foreign floor.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    FloorBinding,
    /// A retained point check does not name a rational point.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Point,
    /// A nested comparison refuses its own first structural clause.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Comparison(crate::numerics::comparison::Error),
    /// The branch zero-width flag differs from the original input.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ZeroWidth,
    /// Zero width carries a forbidden floor-position comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ZeroFloor,
    /// Positive width omits its floor-position comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    MissingFloor,
    /// A target-dependent question lacks its retained inverse target.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Target,
    /// A branch cannot be selected by an operational result.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    BranchOperational,
    /// A branch cannot be selected by an evaluated straddle.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    BranchIndecisive,
    /// A required decided position before the stop is missing.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    MissingBeforeStop,
    /// A point Floor stop is unavailable on the rational floor.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    PointFloor,
    /// A point Floor stop omits its last retained comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    LastFloor,
    /// The point Floor result differs from the retained nested comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    FloorEquality,
    /// An inverse stop cannot carry a fabricated comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    InverseComparison,
    /// Delivery lacks its complete branches and retained ideal.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveryBranches,
    /// Retained range endpoints are reversed.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Range,
    /// A required defining-ridge image is unavailable for grid selection.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    RidgeImage,
    /// The declared grid has no admissible point.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Grid,
    /// Variant one is not an evaluated comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    IndecisiveKind,
    /// Variant one's comparison does not carry INDECISIVE.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    IndecisiveVerdict,
    /// A certified representation refusal is not at Delivery.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    RefusalStage,
    /// A certified refusal contains an operational comparison.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    RefusalKind,
    /// A certified refusal does not carry FAIL.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    RefusalVerdict,
    /// The operational cause lies outside the closed seven.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Cause,
    /// A delivered result lacks its delivered value.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveredValue,
    /// A delivered result also claims a stop.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveredStop,
    /// A delivered result omits its delivery error.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveredError,
    /// A stopped result carries a delivery error.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    StoppedError,
    /// The delivery error differs from the retained ideal and delivered value.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveryErrorRange,
    /// The bound delivery error exceeds the delivery declaration.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    DeliveryErrorBound,
    /// A stopped result omits stopped-at.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    MissingStop,
    /// Stopped-at differs from the result's stage.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    StopStage,
    /// A stopped result also claims a delivered value.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    StoppedValue,
    /// A record contains no attempt.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Empty,
    /// Branches contains no decided position.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    EmptyPrefix,
    /// A later position follows an absent earlier position.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    BrokenPrefix,
    /// A position follows a passing deadband.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    PastEnd,
    /// The prefix contains a position at or after its stop.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    PresentAfterStop,
    /// A direction or cap stop follows a completed hold.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    StopAfterHold,
    /// An incomplete decision carries an ideal.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    EarlyIdeal,
    /// A complete decision omits its ideal.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    MissingIdeal,
    /// The proposal range differs from its recorded defining range.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    ProposalRange,
    /// The ideal range differs from the recorded decision.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    IdealRange,
    /// Delivery requires the decision to be complete.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    IncompleteDecision,
    /// A terminal attempt has a successor.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    Successor,
}

impl From<nrz_cas::Fault> for Error {
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "controller-resource-error",
            source_item = "controller::v2::<Error as From < nrz_cas :: Fault >>::from"
        ),
        ret
    )]
    fn from(fault: nrz_cas::Fault) -> Self {
        let _ = fault;
        Self::Resource
    }
}

fn rat(text: &str, budget: &mut Budget) -> Result<Rational, Error> {
    Rational::parse(text, budget).map_err(|fault| match fault.kind {
        nrz_cas::FaultKind::Exhausted { .. } => Error::Resource,
        nrz_cas::FaultKind::Invalid(_) => Error::Number,
    })
}

fn pair(range: &Range, budget: &mut Budget) -> Result<(Rational, Rational), Error> {
    let lower = rat(&range.lower, budget)?;
    let upper = rat(&range.upper, budget)?;
    if lower.compare(&upper, budget)?.is_gt() {
        return Err(Error::Range);
    }
    Ok((lower, upper))
}

fn zero(budget: &mut Budget) -> Result<crate::binary64::Fraction, Error> {
    crate::binary64::Fraction::new("0".into(), "1".into(), budget.limits().clone()).map_err(|_| Error::Resource)
}

fn verdict(comparison: &FloorComparisonV2) -> Option<u64> {
    match &comparison.result {
        Comparison::Evaluated { verdict, .. } | Comparison::Exact { verdict, .. } => Some(*verdict),
        Comparison::Operational { .. } => None,
    }
}

fn decided(comparison: &FloorComparisonV2) -> Result<u64, Error> {
    let value = verdict(comparison).ok_or(Error::BranchOperational)?;
    if value == 2 {
        return Err(Error::BranchIndecisive);
    }
    Ok(value)
}

fn compare(
    comparison: &FloorComparisonV2,
    exact: Option<(Rational, Rational)>,
    predicate: u64,
    context: &Context<'_>,
    budget: &mut Budget,
) -> Result<(), Error> {
    let strings = exact
        .map(|(left, right)| Ok::<_, Error>((left.exact_string(budget)?, right.exact_string(budget)?)))
        .transpose()?;
    let floor = floor_operand(context.inputs.floor);
    let ridge = match &floor {
        Wall::DefiningRidge(definition) => Some((definition, context.proof)),
        Wall::Rational(_) => None,
    };
    comparison
        .validate_controller(
            strings.as_ref().map(|(left, right)| (left.as_str(), right.as_str())),
            predicate,
            ridge,
            budget,
        )
        .map_err(Error::Comparison)
}

fn floor_operand(floor: Floor) -> Wall {
    match floor {
        Floor::RationalThreeThirtySevenths => Wall::Rational("3/37".into()),
        Floor::RidgeImage => Wall::DefiningRidge(Definition {
            schema: "clean-elasticity-ridge-v1".into(),
            inverse_temperature: "2*ln(2)".into(),
            bleed_squared: "0".into(),
            core_power: "1".into(),
        }),
    }
}

fn point_checks(attempt: &Attempt, context: &Context<'_>, budget: &mut Budget) -> Result<(), Error> {
    for check in &attempt.floor_checks {
        if check.floor != context.inputs.floor {
            return Err(Error::FloorBinding);
        }
        if !matches!(check.wall, Wall::Rational(_)) {
            return Err(Error::Point);
        }
        let reduction = if context.inputs.floor == Floor::RidgeImage {
            let Wall::Rational(wall) = &check.wall else {
                return Err(Error::Point);
            };
            let wall = rat(wall, budget)?;
            u64::from(!wall.is_negative() && !wall.is_zero() && wall.compare(&rat("1", budget)?, budget)?.is_lt())
        } else {
            0
        };
        let expected = Expected {
            question: Question {
                left: check.wall.clone(),
                right: floor_operand(context.inputs.floor),
            },
            reduction,
            predicate: 4,
            threshold: zero(budget)?,
        };
        check
            .validate(&check.wall, context.inputs.floor, &expected, context.proof, budget)
            .map_err(Error::Comparison)?;
    }
    Ok(())
}

fn target(attempt: &Attempt) -> Result<&Range, Error> {
    attempt
        .inverse
        .as_ref()
        .and_then(|inverse| inverse.target.as_ref())
        .ok_or(Error::Target)
}

fn floor_exact(floor: Floor, budget: &mut Budget) -> Result<Option<Rational>, Error> {
    if floor == Floor::RationalThreeThirtySevenths {
        Ok(Some(rat("3/37", budget)?))
    } else {
        Ok(None)
    }
}

fn proposal(attempt: &Attempt, context: &Context<'_>, budget: &mut Budget) -> Result<Option<Rational>, Error> {
    if rat(&context.inputs.width, budget)?.is_zero() {
        return floor_exact(context.inputs.floor, budget);
    }
    let floor = attempt
        .branches
        .as_ref()
        .and_then(|branches| branches.floor.as_ref())
        .ok_or(Error::MissingBeforeStop)?;
    if decided(floor)? == 0 {
        target(attempt)?;
        Ok(None)
    } else {
        floor_exact(context.inputs.floor, budget)
    }
}

fn complete(branches: &Branches) -> bool {
    branches.deadband.as_ref().is_some_and(|value| verdict(value) == Some(0))
        || [
            branches.deadband.as_ref(),
            branches.direction.as_ref(),
            branches.absolute_cap.as_ref(),
            branches.relative_cap.as_ref(),
        ]
        .iter()
        .all(Option::is_some)
}

fn required(value: Option<&FloorComparisonV2>) -> Result<&FloorComparisonV2, Error> {
    value.ok_or(Error::MissingBeforeStop)
}

fn proposal_bounds(attempt: &Attempt, context: &Context<'_>, budget: &mut Budget) -> Result<(Rational, Rational), Error> {
    if let Some(value) = proposal(attempt, context, budget)? {
        return Ok((value.clone(), value));
    }
    let floor_selected = rat(&context.inputs.width, budget)?.is_zero()
        || attempt
            .branches
            .as_ref()
            .and_then(|branches| branches.floor.as_ref())
            .is_some_and(|floor| verdict(floor) == Some(1));
    if floor_selected {
        let image = context
            .proof
            .and_then(|proof| proof.evidence.record.image.as_ref())
            .ok_or(Error::RidgeImage)?;
        pair(image, budget)
    } else {
        pair(target(attempt)?, budget)
    }
}

fn position(
    attempt: &Attempt,
    context: &Context<'_>,
    stage: Stage,
    comparison: &FloorComparisonV2,
    budget: &mut Budget,
) -> Result<(), Error> {
    if stage == Stage::Floor {
        target(attempt)?;
        return compare(comparison, None, 4, context, budget);
    }
    let p = proposal(attempt, context, budget)?;
    let previous = rat(&context.inputs.previous, budget)?;
    let predicate = match stage {
        Stage::Deadband => 1,
        Stage::Direction => 2,
        Stage::AbsoluteCap | Stage::RelativeCap => 4,
        _ => return Err(Error::InverseComparison),
    };
    let right = match stage {
        Stage::Deadband => rat(&context.inputs.deadband, budget)?.mul(&previous, budget)?,
        Stage::AbsoluteCap => rat(&context.inputs.absolute_cap, budget)?,
        Stage::RelativeCap => rat(&context.inputs.relative_cap, budget)?.mul(&previous, budget)?,
        Stage::Direction => previous.clone(),
        _ => return Err(Error::InverseComparison),
    };
    let exact = if let Some(p) = p {
        if stage == Stage::Direction {
            Some((p, previous))
        } else {
            let difference = p.sub(&previous, budget)?;
            let distance = if difference.is_negative() {
                rat("0", budget)?.sub(&difference, budget)?
            } else {
                difference
            };
            Some((distance, right))
        }
    } else {
        None
    };
    compare(comparison, exact, predicate, context, budget)
}

fn branches(attempt: &Attempt, context: &Context<'_>, budget: &mut Budget) -> Result<(), Error> {
    let Some(branches) = &attempt.branches else {
        return Ok(());
    };
    let empty = rat(&context.inputs.width, budget)?.is_zero();
    if branches.zero_width != empty {
        return Err(Error::ZeroWidth);
    }
    if empty && branches.floor.is_some() {
        return Err(Error::ZeroFloor);
    }
    if !empty && branches.floor.is_none() {
        return Err(Error::MissingFloor);
    }
    if branches.floor.is_none()
        && branches.deadband.is_none()
        && branches.direction.is_none()
        && branches.absolute_cap.is_none()
        && branches.relative_cap.is_none()
    {
        return Err(Error::EmptyPrefix);
    }
    if let Some(floor) = &branches.floor {
        position(attempt, context, Stage::Floor, floor, budget)?;
        decided(floor)?;
    }
    let mut absent = false;
    let mut hold = false;
    for (stage, comparison) in [
        (Stage::Deadband, &branches.deadband),
        (Stage::Direction, &branches.direction),
        (Stage::AbsoluteCap, &branches.absolute_cap),
        (Stage::RelativeCap, &branches.relative_cap),
    ] {
        if let Some(comparison) = comparison {
            if hold {
                return Err(Error::PastEnd);
            }
            if absent {
                return Err(Error::BrokenPrefix);
            }
            position(attempt, context, stage, comparison, budget)?;
            let result = decided(comparison)?;
            hold = stage == Stage::Deadband && result == 0;
        } else {
            absent = true;
        }
    }
    if pair(&branches.proposal, budget)? != proposal_bounds(attempt, context, budget)? {
        return Err(Error::ProposalRange);
    }
    if complete(branches) {
        let ideal = branches.ideal.as_ref().ok_or(Error::MissingIdeal)?;
        let expected = if let Some(value) = ideal_exact(attempt, context, budget)? {
            (value.clone(), value)
        } else {
            pair(&branches.proposal, budget)?
        };
        if pair(ideal, budget)? != expected {
            return Err(Error::IdealRange);
        }
    } else if branches.ideal.is_some() {
        return Err(Error::EarlyIdeal);
    }
    Ok(())
}

fn prefix(attempt: &Attempt, context: &Context<'_>, stage: Stage, budget: &mut Budget) -> Result<(), Error> {
    let branches = attempt.branches.as_ref();
    if stage == Stage::Delivery {
        if !branches.is_some_and(complete) {
            return Err(Error::IncompleteDecision);
        }
        return Ok(());
    }
    if stage == Stage::Floor {
        if branches.is_some_and(|branches| !complete(branches)) {
            return Err(Error::IncompleteDecision);
        }
        return Ok(());
    }
    let expected = match stage {
        Stage::InverseGain => 0,
        Stage::Deadband => 1,
        Stage::Direction => 2,
        Stage::AbsoluteCap => 3,
        Stage::RelativeCap => 4,
        _ => unreachable!(),
    };
    if expected > 1
        && branches
            .and_then(|branches| branches.deadband.as_ref())
            .is_some_and(|value| verdict(value) == Some(0))
    {
        return Err(Error::StopAfterHold);
    }
    let empty = rat(&context.inputs.width, budget)?.is_zero();
    let positions = branches.map_or([None; 5], |branches| {
        [
            branches.floor.as_ref(),
            branches.deadband.as_ref(),
            branches.direction.as_ref(),
            branches.absolute_cap.as_ref(),
            branches.relative_cap.as_ref(),
        ]
    });
    for (index, position) in positions.iter().enumerate() {
        if index == 0 && empty {
            continue;
        }
        if index < expected && position.is_none() {
            return Err(Error::MissingBeforeStop);
        }
        if index >= expected && position.is_some() {
            return Err(Error::PresentAfterStop);
        }
    }
    Ok(())
}

fn magnitude(value: Rational, budget: &mut Budget) -> Result<Rational, Error> {
    if value.is_negative() {
        Ok(rat("0", budget)?.sub(&value, budget)?)
    } else {
        Ok(value)
    }
}

fn minimum(left: Rational, right: Rational, budget: &mut Budget) -> Result<Rational, Error> {
    Ok(if left.compare(&right, budget)?.is_le() { left } else { right })
}

fn grid_value(index: u64, quantum: &Rational, budget: &mut Budget) -> Result<Rational, Error> {
    Ok(rat(&index.to_string(), budget)?.mul(quantum, budget)?)
}

fn grid_index(value: &Rational, quantum: &Rational, budget: &mut Budget) -> Result<u64, Error> {
    if value.is_negative() {
        return Ok(0);
    }
    let mut lower = 0_u64;
    let mut upper = 1_u64;
    while grid_value(upper, quantum, budget)?.compare(value, budget)?.is_le() {
        lower = upper;
        upper = upper.checked_mul(2).ok_or(Error::Grid)?;
    }
    while upper - lower > 1 {
        let middle = lower + (upper - lower) / 2;
        if grid_value(middle, quantum, budget)?.compare(value, budget)?.is_le() {
            lower = middle;
        } else {
            upper = middle;
        }
    }
    Ok(lower)
}

fn grid_ceil(value: &Rational, quantum: &Rational, budget: &mut Budget) -> Result<u64, Error> {
    let index = grid_index(value, quantum, budget)?;
    if grid_value(index, quantum, budget)?.compare(value, budget)?.is_lt() {
        index.checked_add(1).ok_or(Error::Grid)
    } else {
        Ok(index)
    }
}

fn nearest(
    value: &Rational,
    quantum: &Rational,
    first: u64,
    last: u64,
    previous: &Rational,
    budget: &mut Budget,
) -> Result<u64, Error> {
    let index = grid_index(value, quantum, budget)?;
    let lower = index.clamp(first, last);
    let upper = index.checked_add(1).ok_or(Error::Grid)?.clamp(first, last);
    let low = grid_value(lower, quantum, budget)?;
    let high = grid_value(upper, quantum, budget)?;
    let low_distance = magnitude(low.sub(value, budget)?, budget)?;
    let high_distance = magnitude(high.sub(value, budget)?, budget)?;
    Ok(match low_distance.compare(&high_distance, budget)? {
        std::cmp::Ordering::Less => lower,
        std::cmp::Ordering::Greater => upper,
        std::cmp::Ordering::Equal => {
            let low_step = magnitude(low.sub(previous, budget)?, budget)?;
            let high_step = magnitude(high.sub(previous, budget)?, budget)?;
            if low_step.compare(&high_step, budget)?.is_le() {
                lower
            } else {
                upper
            }
        }
    })
}

fn ideal_exact(attempt: &Attempt, context: &Context<'_>, budget: &mut Budget) -> Result<Option<Rational>, Error> {
    let branches = attempt.branches.as_ref().ok_or(Error::DeliveryBranches)?;
    let previous = rat(&context.inputs.previous, budget)?;
    if decided(required(branches.deadband.as_ref())?)? == 0 {
        return Ok(Some(previous));
    }
    if decided(required(branches.absolute_cap.as_ref())?)? == 0 || decided(required(branches.relative_cap.as_ref())?)? == 0 {
        let cap = minimum(
            rat(&context.inputs.absolute_cap, budget)?,
            rat(&context.inputs.relative_cap, budget)?.mul(&previous, budget)?,
            budget,
        )?;
        return Ok(Some(if decided(required(branches.direction.as_ref())?)? == 0 {
            previous.sub(&cap, budget)?
        } else {
            previous.add(&cap, budget)?
        }));
    }
    proposal(attempt, context, budget)
}

fn grid_bounds(
    attempt: &Attempt,
    context: &Context<'_>,
    quantum: &Rational,
    previous: &Rational,
    budget: &mut Budget,
) -> Result<(u64, u64), Error> {
    let cap = minimum(
        rat(&context.inputs.absolute_cap, budget)?,
        rat(&context.inputs.relative_cap, budget)?.mul(previous, budget)?,
        budget,
    )?;
    let cap_first = grid_ceil(&previous.sub(&cap, budget)?, quantum, budget)?;
    let last = grid_index(&previous.add(&cap, budget)?, quantum, budget)?;
    let floor_upper = if let Some(floor) = floor_exact(context.inputs.floor, budget)? {
        floor
    } else {
        let image = context
            .proof
            .and_then(|proof| proof.evidence.record.image.as_ref())
            .ok_or(Error::RidgeImage)?;
        pair(image, budget)?.1
    };
    let mut first = cap_first.max(grid_ceil(&floor_upper, quantum, budget)?);
    if context.inputs.floor == Floor::RidgeImage {
        while first > cap_first {
            let point = grid_value(first - 1, quantum, budget)?.exact_string(budget)?;
            let found = attempt
                .floor_checks
                .iter()
                .find(|check| check.wall == Wall::Rational(point.clone()));
            if found.is_some_and(|check| verdict(&check.comparison) == Some(0)) {
                first -= 1;
            } else {
                break;
            }
        }
    }
    if first > last {
        return Err(Error::Grid);
    }
    Ok((first, last))
}

fn delivery(attempt: &Attempt, context: &Context<'_>, comparison: &FloorComparisonV2, budget: &mut Budget) -> Result<(), Error> {
    let branches = attempt.branches.as_ref().ok_or(Error::DeliveryBranches)?;
    let (lower, upper) = pair(branches.ideal.as_ref().ok_or(Error::MissingIdeal)?, budget)?;
    let Delivery::Grid { quantum, maximum_error } = &context.inputs.delivery else {
        return compare(comparison, Some((lower, upper)), 3, context, budget);
    };
    let quantum = rat(quantum, budget)?;
    let previous = rat(&context.inputs.previous, budget)?;
    let (first, last) = grid_bounds(attempt, context, &quantum, &previous, budget)?;
    let left = nearest(&lower, &quantum, first, last, &previous, budget)?;
    let right = nearest(&upper, &quantum, first, last, &previous, budget)?;
    let ideal = ideal_exact(attempt, context, budget)?;
    if left != right {
        let low = grid_value(left, &quantum, budget)?;
        let high = grid_value(left.checked_add(1).ok_or(Error::Grid)?, &quantum, budget)?;
        let midpoint = low.add(&high, budget)?.div(&rat("2", budget)?, budget)?;
        let tie = nearest(&midpoint, &quantum, first, last, &previous, budget)?;
        let predicate = if tie == left { 1 } else { 2 };
        return compare(comparison, ideal.map(|ideal| (ideal, midpoint)), predicate, context, budget);
    }
    let exact = if let Some(ideal) = ideal {
        let selected = grid_value(left, &quantum, budget)?;
        Some((magnitude(ideal.sub(&selected, budget)?, budget)?, rat(maximum_error, budget)?))
    } else {
        None
    };
    compare(comparison, exact, 1, context, budget)
}

fn stopped_comparison(
    attempt: &Attempt,
    context: &Context<'_>,
    stage: Stage,
    comparison: &FloorComparisonV2,
    budget: &mut Budget,
) -> Result<(), Error> {
    match stage {
        Stage::Floor => {
            if attempt.inverse.as_ref().and_then(|inverse| inverse.target.as_ref()).is_some() && attempt.branches.is_none() {
                position(attempt, context, Stage::Floor, comparison, budget)
            } else {
                if context.inputs.floor != Floor::RidgeImage {
                    return Err(Error::PointFloor);
                }
                let last = attempt.floor_checks.last().ok_or(Error::LastFloor)?;
                if comparison != &last.comparison {
                    return Err(Error::FloorEquality);
                }
                Ok(())
            }
        }
        Stage::InverseGain => Err(Error::InverseComparison),
        Stage::Delivery => delivery(attempt, context, comparison, budget),
        _ => position(attempt, context, stage, comparison, budget),
    }
}

fn result(attempt: &Attempt, context: &Context<'_>, budget: &mut Budget) -> Result<Option<Stage>, Error> {
    if let ResultKind::Indecisive { stage, .. } | ResultKind::Operational { stage, .. } | ResultKind::Refused { stage, .. } =
        &attempt.result
    {
        prefix(attempt, context, *stage, budget)?;
    }

    match &attempt.result {
        ResultKind::Delivered => Ok(None),
        ResultKind::Operational { stage, cause } => {
            if !(1..=7).contains(cause) {
                return Err(Error::Cause);
            }
            Ok(Some(*stage))
        }
        ResultKind::Indecisive { stage, comparison } => {
            stopped_comparison(attempt, context, *stage, comparison, budget)?;
            let Comparison::Evaluated { verdict, .. } = &comparison.result else {
                return Err(Error::IndecisiveKind);
            };
            if *verdict != 2 {
                return Err(Error::IndecisiveVerdict);
            }
            Ok(Some(*stage))
        }
        ResultKind::Refused { stage, comparison } => {
            stopped_comparison(attempt, context, *stage, comparison, budget)?;
            if *stage != Stage::Delivery {
                return Err(Error::RefusalStage);
            }
            let value = verdict(comparison).ok_or(Error::RefusalKind)?;
            if value != 1 {
                return Err(Error::RefusalVerdict);
            }
            Ok(Some(*stage))
        }
    }
}

fn validate_context(context: &Context<'_>, expected: &Context<'_>, precision: u32, budget: &mut Budget) -> Result<(), Error> {
    if context.procedure != expected.procedure {
        return Err(Error::Procedure);
    }
    if context.inputs != expected.inputs {
        return Err(Error::Inputs);
    }
    let Precision::AbsoluteWidthBits(sequence) = &context.procedure.precision else {
        return Err(Error::PrecisionKind);
    };
    if context.index != expected.index {
        return Err(Error::AttemptIndex);
    }
    let bits = sequence.get(context.index).ok_or(Error::AttemptIndex)?;
    if precision != *bits {
        return Err(Error::Precision);
    }
    if rat(&context.inputs.width, budget)?.is_negative() {
        return Err(Error::Width);
    }
    let previous = rat(&context.inputs.previous, budget)?;
    if previous.is_negative() || previous.is_zero() {
        return Err(Error::Previous);
    }
    if let Delivery::Grid { quantum, maximum_error } = &context.inputs.delivery {
        let q = rat(quantum, budget)?;
        if q.is_negative() || q.is_zero() {
            return Err(Error::DeliveryDeclaration);
        }
        if rat(maximum_error, budget)?.compare(&q, budget)?.is_lt() {
            return Err(Error::DeliveryDeclaration);
        }
    }
    Ok(())
}

impl Attempt {
    /// Validate the explicitly selected attempt against independently supplied context.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    /// # Errors
    /// Returns the first structural refusal, without evaluating an enclosure's soundness.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "controller-attempt-validate",
            source_item = "controller::v2::Attempt::validate"
        ),
        ret
    )]
    pub fn validate(&self, context: &Context<'_>, expected: &Context<'_>, budget: &mut Budget) -> Result<(), Error> {
        validate_context(context, expected, self.precision, budget)?;
        point_checks(self, context, budget)?;
        branches(self, context, budget)?;
        let stage = result(self, context, budget)?;
        if let Some(stage) = stage {
            let stopped = self.stopped_at.ok_or(Error::MissingStop)?;
            if stopped != stage {
                return Err(Error::StopStage);
            }
            if self.delivered.is_some() {
                return Err(Error::StoppedValue);
            }
            if self.delivery_error.is_some() {
                return Err(Error::StoppedError);
            }
        } else {
            if !self.branches.as_ref().is_some_and(complete) {
                return Err(Error::IncompleteDecision);
            }
            if self.delivered.is_none() {
                return Err(Error::DeliveredValue);
            }
            if self.stopped_at.is_some() {
                return Err(Error::DeliveredStop);
            }
            let error = self.delivery_error.as_ref().ok_or(Error::DeliveredError)?;
            let ideal = self
                .branches
                .as_ref()
                .and_then(|branches| branches.ideal.as_ref())
                .ok_or(Error::MissingIdeal)?;
            let (lower, upper) = pair(ideal, budget)?;
            let selected = rat(self.delivered.as_deref().ok_or(Error::DeliveredValue)?, budget)?;
            let lower = lower.sub(&selected, budget)?;
            let upper = upper.sub(&selected, budget)?;
            let zero = rat("0", budget)?;
            let bound = if !lower.is_negative() {
                (lower, upper)
            } else if upper.is_negative() || upper.is_zero() {
                (zero.sub(&upper, budget)?, zero.sub(&lower, budget)?)
            } else {
                let magnitude = zero.sub(&lower, budget)?;
                let maximum = if magnitude.compare(&upper, budget)?.is_gt() {
                    magnitude
                } else {
                    upper
                };
                (zero, maximum)
            };
            let actual = pair(error, budget)?;
            if actual.0.compare(&bound.0, budget)?.is_ne() || actual.1.compare(&bound.1, budget)?.is_ne() {
                return Err(Error::DeliveryErrorRange);
            }
            let within = match &context.inputs.delivery {
                Delivery::ExactRational => bound.0.is_zero() && bound.1.is_zero(),
                Delivery::Grid { maximum_error, .. } => bound.1.compare(&rat(maximum_error, budget)?, budget)?.is_le(),
            };
            if !within {
                return Err(Error::DeliveryErrorBound);
            }
        }
        Ok(())
    }
}

impl Record {
    /// Validate ordered attempts without manufacturing a top-level verdict.
    /// (´[ROOT-dec:design:comparison-verdict-record]´)
    /// # Errors
    /// Refuses a foreign context, an empty sequence, a nested violation or a terminal successor.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "controller-record-validate",
            source_item = "controller::v2::Record::validate"
        ),
        ret
    )]
    pub fn validate(
        &self,
        expected_procedure: &Procedure,
        expected_inputs: &Inputs,
        proof: Option<&DefiningProof<'_>>,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        if self.procedure != *expected_procedure {
            return Err(Error::Procedure);
        }
        if self.inputs != *expected_inputs {
            return Err(Error::Inputs);
        }
        if self.attempts.is_empty() {
            return Err(Error::Empty);
        }
        for (index, attempt) in self.attempts.iter().enumerate() {
            let context = Context {
                procedure: &self.procedure,
                inputs: &self.inputs,
                index,
                proof,
            };
            let expected = Context {
                procedure: expected_procedure,
                inputs: expected_inputs,
                index,
                proof,
            };
            attempt.validate(&context, &expected, budget)?;
            if matches!(attempt.result, ResultKind::Delivered | ResultKind::Refused { .. }) && index + 1 < self.attempts.len() {
                return Err(Error::Successor);
            }
        }
        Ok(())
    }
}
