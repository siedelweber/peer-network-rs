//! Enclose a frozen held base entry without replacing its cells or exact terms.
//! (´def:compiler:real-base´)

use crate::{
    base::{BaseEntry, BaseScore},
    solve::{BoundProcedure, ProcedureError},
};
use pn_records::primitive::{Attachment, Goal, Node, PrimitiveRecord, Query};

/// Exact entries remain exact; held entries retain their complete source and checked evidence.
/// (´def:compiler:real-base´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub original: BaseEntry,
    pub primitive: Option<PrimitiveRecord>,
}

/// Resolve one frozen base entry through the declared scalar adapter, without changing support.
/// (´[ROOT-alg:design:base]´)
/// # Errors
/// Refuses an absent entry, unavailable declaration or a failed scalar request.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "real_base::evaluate"
    ),
    ret
)]
pub fn evaluate(
    bound: &BoundProcedure<'_>,
    source: &str,
    target: &str,
    interrupt_at: Option<u64>,
) -> Result<Evaluation, ProcedureError> {
    run(bound, source, target, None, interrupt_at)
}

/// Rebuild the expected query from the frozen entry before checking supplied evidence.
/// (´def:compiler:real-base´)
/// # Errors
/// Refuses absent or exact entries, changed scope and invalid scalar evidence.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "real_base::replay"
    ),
    ret
)]
pub fn replay(
    bound: &BoundProcedure<'_>,
    source: &str,
    target: &str,
    attachment: &Attachment,
    interrupt_at: Option<u64>,
) -> Result<Evaluation, ProcedureError> {
    run(bound, source, target, Some(attachment), interrupt_at)
}

fn run(
    bound: &BoundProcedure<'_>,
    source: &str,
    target: &str,
    attachment: Option<&Attachment>,
    interrupt_at: Option<u64>,
) -> Result<Evaluation, ProcedureError> {
    bound.preflight()?;
    let (state, procedure) = bound.inputs();
    let original = state
        .view()
        .base
        .rows
        .get(source)
        .and_then(|row| row.get(target))
        .ok_or(ProcedureError::BaseEntry)?
        .clone();
    let BaseScore::Held { exact_part, terms } = &original.score else {
        if attachment.is_some() {
            return Err(ProcedureError::BaseEntry);
        }
        return Ok(Evaluation {
            original,
            primitive: None,
        });
    };
    let mut nodes = vec![Node::Rational(exact_part.clone())];
    let mut sum = 0;
    for term in terms {
        let radicand = nodes.len();
        nodes.push(Node::Rational(term.radicand.clone()));
        nodes.push(Node::SquareRoot(radicand));
        nodes.push(Node::Rational(term.domain_factor.clone()));
        nodes.push(Node::Multiply(radicand + 1, radicand + 2));
        nodes.push(Node::Add(sum, radicand + 3));
        sum = radicand + 4;
    }
    let query = Query {
        coordinates: Vec::new(),
        nodes,
        target: sum,
        goal: Goal::Width,
    };
    let evidence = if let Some(attachment) = attachment {
        pn_graph::numeric::replay(procedure, &query, attachment, interrupt_at)?
    } else {
        pn_graph::numeric::evaluate(procedure, &query, interrupt_at)?
    };
    let precision = procedure
        .enclosure
        .as_ref()
        .ok_or(ProcedureError::Unsupported)?
        .refinement
        .precision;
    Ok(Evaluation {
        original,
        primitive: Some(PrimitiveRecord {
            query,
            precision,
            evidence,
        }),
    })
}
