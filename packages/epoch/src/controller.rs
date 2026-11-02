//! Bind controller inputs to one frozen completed epoch and independently check delivery.
//! (´[ROOT-alg:design:production-wall-controller]´)

use crate::{
    admission::{AdmissionRefusal, Comparison, Delivery, ScheduleDeclaration, ScheduleInput, Stop},
    fence::Search,
    solve::BoundProcedure,
};
use nrz_cas::{Rational, limits::Budget};
use pn_graph::numeric::ridge::CheckedRidge;
use pn_records::{
    controller::{Inputs, Record, Stage, Verdict},
    primitive::Range,
    solve::{Precision, Procedure},
};

/// Finite inverse-search declarations, separate from measured epoch inputs.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InverseSearch {
    pub bracket: Range,
    pub stopping_width: String,
    pub maximum_steps: u64,
}

/// Candidate publication retains the epoch certificate and exact rational burn image.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub declaration: ScheduleInput,
    pub search: InverseSearch,
    pub fence: Search,
    pub controller: Record,
    pub burn_image: Option<String>,
}

/// Only independent replay creates this immutable controller result, not admission evidence.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Debug)]
pub struct CheckedProposal {
    evidence: Evidence,
}

/// Typed controller refusals precede the later effective-schedule and admission joins.
/// (´[ROOT-alg:design:production-wall-controller]´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("controller refusal: {0}")]
    Refused(#[from] AdmissionRefusal),
    #[error("frozen fence: {0}")]
    Fence(#[from] crate::fence::Error),
    #[error("controller evidence: {0}")]
    Kernel(#[from] pn_graph::numeric::controller::Error),
    #[error("bounded exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
}

fn inputs(
    bound: &BoundProcedure<'_>,
    declared: &ScheduleDeclaration,
    search: &InverseSearch,
    fence: &Search,
) -> Result<(Procedure, Inputs), Error> {
    let (prepared, hull) = crate::fence::prepare(bound)?;
    let (state, p) = bound.inputs();
    if !matches!(state.package(), crate::compiler::CompiledSource::Published(_)) {
        return Err(AdmissionRefusal::Evidence.into());
    }
    let d = declared.input();
    let init = &d.initialization;
    let parameters = init.parameters.as_ref().ok_or(AdmissionRefusal::Evidence)?;
    let floor = init.floor.ok_or(AdmissionRefusal::Evidence)?;
    let mut b = Budget::new(p.enclosure.as_ref().ok_or(AdmissionRefusal::Evidence)?.operation.clone())?;
    let price = state.package().input().prices.last().ok_or(AdmissionRefusal::Evidence)?;
    if price.numeraire() != &d.numeraire
        || Rational::parse(&p.margin, &mut b)? != Rational::parse(&parameters.margin, &mut b)?
        || state
            .package()
            .input()
            .inputs
            .last()
            .ok_or(AdmissionRefusal::Evidence)?
            .constants()
            .content()
            .floor
            != floor
    {
        return Err(AdmissionRefusal::Evidence.into());
    }
    let accepted = fence.selected.as_ref().ok_or(AdmissionRefusal::Operational(Stop::Work))?;
    let charter = p.grid.first().ok_or(AdmissionRefusal::Evidence)?;
    let cumulative = Rational::parse(&prepared.cumulative_tilt, &mut b)?
        .mul(&Rational::parse(charter, &mut b)?, &mut b)?
        .exact_string(&mut b)?;
    let mut policy = p.clone();
    policy.precision = Precision::AbsoluteWidthBits(d.refinement.precision_bits.clone());
    policy
        .enclosure
        .as_mut()
        .ok_or(AdmissionRefusal::Evidence)?
        .refinement
        .precision = *d.refinement.precision_bits.first().ok_or(AdmissionRefusal::Evidence)?;
    let input = Inputs {
        width: prepared.width,
        empty_live_domain: hull.is_empty(),
        accepted_rung: accepted.clone(),
        cumulative_tilt: cumulative,
        bleed_squared: prepared.bleed_squared,
        previous: price.wall().exact().into(),
        floor,
        absolute_cap: parameters.absolute_cap.clone(),
        relative_cap: parameters.relative_cap.clone(),
        deadband: parameters.deadband.clone(),
        bracket: search.bracket.clone(),
        stopping_width: search.stopping_width.clone(),
        maximum_steps: search.maximum_steps,
        maximum_work: d.refinement.maximum_work,
        maximum_replay_work: d.refinement.maximum_replay_work,
        delivery: match &d.delivery {
            Delivery::ExactRational => pn_records::controller::Delivery::ExactRational,
            Delivery::Grid { quantum, maximum_error } => pn_records::controller::Delivery::Grid {
                quantum: quantum.clone(),
                maximum_error: maximum_error.clone(),
            },
        },
    };
    Ok((policy, input))
}
fn image(p: &Procedure, d: &ScheduleDeclaration, r: &Record) -> Result<Option<String>, Error> {
    let Some(wall) = r.attempts.last().and_then(|a| a.delivered.as_ref()) else {
        return Ok(None);
    };
    let mut b = Budget::new(p.enclosure.as_ref().ok_or(AdmissionRefusal::Evidence)?.operation.clone())?;
    Ok(Some(
        Rational::parse(wall, &mut b)?
            .mul(&Rational::parse(d.input().numeraire.amount().exact(), &mut b)?, &mut b)?
            .exact_string(&mut b)?,
    ))
}

/// Bind width, chartered profile and current rational wall to the completed compiled epoch.
/// (´[ROOT-alg:design:production-wall-controller]´)
/// # Errors
/// Refuses unsupported frozen profiles, inconsistent declarations and bounded kernel failures.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "controller::evaluate"
    ),
    ret
)]
pub fn evaluate(
    bound: &BoundProcedure<'_>,
    d: &ScheduleDeclaration,
    search: &InverseSearch,
    ridge: Option<&CheckedRidge>,
) -> Result<Evidence, Error> {
    let fence = crate::fence::search(bound, None)?;
    let (p, input) = inputs(bound, d, search, &fence)?;
    let controller = pn_graph::numeric::controller::evaluate(&p, &input, ridge)?;
    let burn_image = image(&p, d, &controller)?;
    Ok(Evidence {
        declaration: d.input().clone(),
        search: search.clone(),
        fence,
        controller,
        burn_image,
    })
}

/// Rebuild the frozen epoch joins, fence, inverse and delivery before exposing a checked proposal.
/// (´[ROOT-alg:design:production-wall-controller]´)
/// # Errors
/// Refuses altered inputs or evidence, unresolved comparisons and uncertified rational delivery.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "controller::replay"
    ),
    ret
)]
pub fn replay(
    bound: &BoundProcedure<'_>,
    d: &ScheduleDeclaration,
    search: &InverseSearch,
    ridge: Option<&CheckedRidge>,
    e: &Evidence,
) -> Result<CheckedProposal, Error> {
    if e.declaration != *d.input() || e.search != *search || e.fence != crate::fence::search(bound, None)? {
        return Err(AdmissionRefusal::Evidence.into());
    }
    let (p, input) = inputs(bound, d, search, &e.fence)?;
    let checked = pn_graph::numeric::controller::replay(&p, &input, ridge, &e.controller)?;
    if image(&p, d, &checked)? != e.burn_image {
        return Err(AdmissionRefusal::Evidence.into());
    }
    match checked.verdict {
        Verdict::Delivered => Ok(CheckedProposal { evidence: e.clone() }),
        Verdict::Indecisive => {
            let comparison = match checked.attempts.last().and_then(|a| a.stopped_at) {
                Some(Stage::Floor) => Comparison::Floor,
                Some(Stage::InverseGain) => Comparison::InverseGain,
                Some(Stage::Deadband) => Comparison::Deadband,
                Some(Stage::StepCap) => Comparison::StepCap,
                Some(Stage::Delivery) | None => Comparison::DeliveryError,
            };
            Err(AdmissionRefusal::Indecisive(comparison).into())
        }
        Verdict::DeliveryRefused => Err(AdmissionRefusal::Delivery.into()),
    }
}
impl CheckedProposal {
    /// Borrow independently replayed evidence; schedule activation and admission remain separate.
    /// (´[ROOT-alg:design:production-wall-controller]´)
    /// Justified: Immutable access inherits independent controller replay and supplies no authority.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}
