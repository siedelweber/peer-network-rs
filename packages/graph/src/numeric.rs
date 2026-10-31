//! Certified scalar requests in fresh stores with independently replayable attachments.
//! (´def:numerics:primitive-adapter´)

pub mod activation;
mod scope;

use nrz_cas::{
    enclosure::{EnclosureOutcome, EnclosureReport, UndecidedReason},
    limits::Budget,
};
use pn_records::{
    primitive::{Attachment, Outcome, PrimitiveEvidence, Query, Schema},
    solve::{Precision, Primitive, Procedure},
};

/// Closed names are checked independently of the backend's display name.
/// (´def:numerics:primitive-adapter´)
pub const SCHEMAS: [&str; 9] = [
    "enclosure.rational-inclusion",
    "enclosure.root-grid",
    "enclosure.log-atanh",
    "enclosure.exp-taylor",
    "enclosure.sigmoid-compose",
    "enclosure.tanh-compose",
    "enclosure.positive-power",
    "enclosure.smooth-derivative",
    "enclosure.clamp-generalized",
];

/// Refusals provide no mathematical verdict, including invalid certificate evidence.
/// (´def:numerics:primitive-adapter´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported primitive or precision under open:design:numeric-backend")]
    Unsupported,
    #[error("inverse gain remains under open:design:reference-wall-route")]
    InverseGain,
    #[error("matrix or local inclusion remains under open:design:nrz-capabilities")]
    Composition,
    #[error("invalid numerical declaration or ordered query")]
    Declaration,
    #[error("unknown schema, version or mismatched certificate inventory")]
    Schema,
    #[error("invalid certificate or original-scope join: {0}")]
    InvalidCertificate(nrz_cas::Fault),
    #[error("nrz request or evidence refusal: {0}")]
    Backend(#[from] nrz_cas::Fault),
}

/// Preflight admits the explicit scalar inventory, never an inference from a backend name.
/// (´[ROOT-rule:design:backend-evidence]´)
/// # Errors
/// Refuses undeclared limits, binary-format precision and held compositions.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::preflight"
    ),
    ret
)]
pub fn preflight(procedure: &Procedure) -> Result<(), Error> {
    if procedure.backend != "nrz-cas" {
        return Err(Error::Unsupported);
    }
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let Precision::AbsoluteWidthBits(bits) = &procedure.precision else {
        return Err(Error::Unsupported);
    };
    policy.store.validate()?;
    policy.operation.validate()?;
    if bits.is_empty()
        || bits[0] == 0
        || bits.windows(2).any(|pair| pair[0] >= pair[1])
        || policy.operation.work > policy.store.work
        || policy.operation.work > procedure.maximum_work
        || policy.refinement.version != 1
        || policy.refinement.rounds == 0
        || u64::from(policy.refinement.rounds) > procedure.maximum_iterations
        || !bits.contains(&policy.refinement.precision)
        || bits
            .iter()
            .any(|p| p.checked_add(2).is_none_or(|grid| grid > policy.refinement.grid_ceiling))
        || procedure.primitives.is_empty()
    {
        return Err(Error::Declaration);
    }
    for primitive in &procedure.primitives {
        match primitive {
            Primitive::Matrix | Primitive::Krawczyk => return Err(Error::Composition),
            Primitive::InverseGain => return Err(Error::InverseGain),
            Primitive::Rational
            | Primitive::Root
            | Primitive::Logarithm
            | Primitive::Exponential
            | Primitive::Sigmoid
            | Primitive::Tanh
            | Primitive::Power
            | Primitive::SmoothDerivative
            | Primitive::ClampGeneralized => {}
        }
    }
    Ok(())
}

fn schemas(input: &[Schema]) -> Result<(), Error> {
    for (index, schema) in input.iter().enumerate() {
        if schema.version != 1
            || !SCHEMAS.contains(&schema.name.as_str())
            || input[..index].iter().any(|old| old.name == schema.name)
        {
            return Err(Error::Schema);
        }
    }
    if input.is_empty() {
        return Err(Error::Schema);
    }
    Ok(())
}

fn mapped(report: EnclosureReport, usage: &nrz_cas::limits::BudgetUsage, width_only: bool) -> Result<PrimitiveEvidence, Error> {
    if width_only && matches!(report.outcome, EnclosureOutcome::Proved | EnclosureOutcome::Refuted)
        || !width_only && report.outcome == EnclosureOutcome::Bound
    {
        return Err(Error::Declaration);
    }
    let (bounds, attachment) = if let Some(checked) = report.checked {
        let schemas = checked
            .formal_schemas()
            .iter()
            .map(|schema| Schema {
                name: schema.name.into(),
                version: schema.version,
            })
            .collect::<Vec<_>>();
        self::schemas(&schemas)?;
        (
            Some(checked.interval().clone()),
            Some(Attachment {
                schemas,
                certificate: checked.certificate().clone(),
            }),
        )
    } else {
        (None, None)
    };
    let outcome = match report.outcome {
        EnclosureOutcome::Proved => Outcome::Pass,
        EnclosureOutcome::Refuted => Outcome::Fail,
        EnclosureOutcome::Bound => Outcome::Bound,
        EnclosureOutcome::Undecided(UndecidedReason::DomainBoundary) if bounds.is_none() => Outcome::DomainBoundary,
        EnclosureOutcome::Undecided(reason) => Outcome::Indecisive(reason),
        EnclosureOutcome::Exhausted => Outcome::Exhausted,
        EnclosureOutcome::Unsupported => Outcome::Unsupported,
        EnclosureOutcome::Interrupted => Outcome::Interrupted,
    };
    if matches!(
        outcome,
        Outcome::Pass | Outcome::Fail | Outcome::Bound | Outcome::Indecisive(_)
    ) && bounds.is_none()
    {
        return Err(Error::Declaration);
    }
    Ok(PrimitiveEvidence {
        outcome,
        bounds,
        attachment,
        work: usage.work,
        usage: *usage,
        evaluation_work: report.work,
        precision_met: report.precision_met,
        completed_rounds: report.completed_rounds,
        resource_fault: report.resource_fault,
    })
}

fn run(
    procedure: &Procedure,
    query: &Query,
    evidence: Option<&Attachment>,
    interrupt_at: Option<u64>,
) -> Result<PrimitiveEvidence, Error> {
    preflight(procedure)?;
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    if let Some(evidence) = evidence {
        schemas(&evidence.schemas)?;
    }
    let mut budget = Budget::new(policy.operation.clone())?;
    run_budget(procedure, query, evidence, interrupt_at, &mut budget)
}

fn run_budget(
    procedure: &Procedure,
    query: &Query,
    evidence: Option<&Attachment>,
    interrupt_at: Option<u64>,
    budget: &mut Budget,
) -> Result<PrimitiveEvidence, Error> {
    let policy = procedure.enclosure.as_ref().ok_or(Error::Unsupported)?;
    let (mut cas, request) = scope::build(procedure, query, budget)?;
    let mut interrupt = |usage: nrz_cas::limits::BudgetUsage| interrupt_at.is_some_and(|limit| usage.work >= limit);
    let report = if let Some(evidence) = evidence {
        cas.check_enclosure(&request, policy.refinement, &evidence.certificate, budget, &mut interrupt)
            .map_err(|fault| match fault.kind {
                nrz_cas::FaultKind::Invalid(_) => Error::InvalidCertificate(fault),
                nrz_cas::FaultKind::Exhausted { .. } => Error::Backend(fault),
            })?
    } else {
        cas.enclose(&request, policy.refinement, budget, &mut interrupt)?
    };
    let result = mapped(
        report,
        &budget.usage(),
        matches!(query.goal, pn_records::primitive::Goal::Width),
    )?;
    if let (Some(supplied), Some(checked)) = (evidence, &result.attachment)
        && supplied.schemas != checked.schemas
    {
        return Err(Error::Schema);
    }
    Ok(result)
}

/// Evaluate one original request in a new explicitly bounded store; retain nothing across calls.
/// (´[ROOT-rule:design:refinement]´)
/// # Errors
/// Refuses declarations, domains and malformed scope; no refusal is a mathematical FAIL.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::evaluate"
    ),
    ret
)]
pub fn evaluate(procedure: &Procedure, query: &Query, interrupt_at: Option<u64>) -> Result<PrimitiveEvidence, Error> {
    run(procedure, query, None, interrupt_at)
}

/// Rebuild the expected original scope in a fresh store and replay the supplied certificate.
/// (´[ROOT-rule:design:backend-evidence]´)
/// # Errors
/// Refuses changed scope, unknown schemas, invalid certificates or unavailable capabilities.
#[tracing::instrument(
    name = "sig:design:graph",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "sig:design:graph",
        source_item = "numeric::replay"
    ),
    ret
)]
pub fn replay(
    procedure: &Procedure,
    expected: &Query,
    evidence: &Attachment,
    interrupt_at: Option<u64>,
) -> Result<PrimitiveEvidence, Error> {
    run(procedure, expected, Some(evidence), interrupt_at)
}
