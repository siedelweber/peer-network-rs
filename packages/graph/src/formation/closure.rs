//! Successor structural reconstruction without a removal or holder input.
//! (´[ROOT-amend:identity:closure-components]´)

use std::collections::BTreeMap;

use petgraph::stable_graph::StableDiGraph;
use pn_records::ActId;
use pn_records::SettlementReferences;
use pn_records::closure::{ClosureAct, ClosureHeader, ClosureHistory};

use super::{CompleteProjection, FormationGraph, LegView, StructuralView};
use crate::registration::FamilyError;

/// Approval of the exact retained successor act, without a removal method.
pub trait ClosureApproval<H: ClosureHeader>: std::fmt::Debug {
    fn approval(&self, act: &ClosureAct<H>) -> bool;
}

/// A successor graph is distinct by value; `graph()` lends the structural graph.
/// No historical title, recognition or epoch consumer is admitted over that loan.
#[derive(Clone, Debug)]
pub struct ClosureFormationGraph(FormationGraph);

impl ClosureFormationGraph {
    #[must_use]
    #[tracing::instrument(
        name = "alg:design:formation",
        fields(
            execution_owner = "GRAPH",
            claim_owner = "ROOT",
            claim_label = "alg:design:formation",
            source_item = "formation::closure::ClosureFormationGraph::graph"
        ),
        ret
    )]
    pub fn graph(&self) -> &FormationGraph {
        &self.0
    }
}

/// The five structural meanings; no removal refusal exists here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClosureGraphError {
    #[error("unsupported act family")]
    UnsupportedFamily,
    #[error("invalid structural incidence")]
    Incidence,
    #[error("approval not established")]
    Unapproved,
    #[error("graph capacity exhausted")]
    Capacity,
    #[error("graph differs from reconstruction")]
    GraphMismatch,
}

impl From<FamilyError> for ClosureGraphError {
    /// Justified: Pure conversion of the five structural refusals inherits its enclosing reconstruction boundary.
    fn from(error: FamilyError) -> Self {
        match error {
            FamilyError::UnsupportedFamily => Self::UnsupportedFamily,
            FamilyError::Incidence => Self::Incidence,
            FamilyError::Unapproved => Self::Unapproved,
            FamilyError::Capacity => Self::Capacity,
            FamilyError::GraphMismatch => Self::GraphMismatch,
        }
    }
}

fn view<H: ClosureHeader>(act: &ClosureAct<H>) -> StructuralView<'_> {
    StructuralView {
        id: act.id(),
        body: act.header().body(),
        legs: act
            .header()
            .legs()
            .into_iter()
            .map(|leg| LegView {
                id: leg.id,
                source: leg.source,
                target: leg.target,
            })
            .collect(),
        references: act.header().protocol_references(),
        metadata: crate::metadata::ActMetadata {
            position: (act.epoch(), act.position()),
            logical_time: act.logical_time(),
        },
    }
}

fn checked_project<H: ClosureHeader>(
    act: &ClosureAct<H>,
    acts: &BTreeMap<&ActId, &ClosureAct<H>>,
    approval: &impl ClosureApproval<H>,
    replay: bool,
) -> Result<Vec<CompleteProjection>, ClosureGraphError> {
    if acts.get(act.id()).copied().is_none_or(|found| !std::ptr::eq(found, act)) {
        return Err(ClosureGraphError::Incidence);
    }
    if !replay
        && act.header().body().causal_parents().into_iter().any(|parent| {
            acts.get(parent)
                .is_none_or(|parent| (parent.epoch(), parent.position()) >= (act.epoch(), act.position()))
        })
    {
        return Err(ClosureGraphError::Incidence);
    }
    if let Some(references) = &act.header().body().settlement {
        let (SettlementReferences::Accept { settles } | SettlementReferences::Ratify { settles, .. }) = references;
        settlement_target(settles, act, acts, approval, replay)?;
        if let SettlementReferences::Ratify { accepts, .. } = references {
            settlement_target(accepts, act, acts, approval, replay)?;
        }
    }
    super::project(&view(act), &|| approval.approval(act)).map_err(Into::into)
}

fn settlement_target<H: ClosureHeader>(
    id: &ActId,
    before: &ClosureAct<H>,
    acts: &BTreeMap<&ActId, &ClosureAct<H>>,
    approval: &impl ClosureApproval<H>,
    replay: bool,
) -> Result<(), ClosureGraphError> {
    let target = acts.get(id).copied();
    if replay && target.is_none_or(|target| (target.epoch(), target.position()) >= (before.epoch(), before.position())) {
        return Ok(());
    }
    let target = target.ok_or(ClosureGraphError::Incidence)?;
    if (target.epoch(), target.position()) >= (before.epoch(), before.position()) {
        return Err(ClosureGraphError::Incidence);
    }
    checked_project(target, acts, approval, replay)?;
    Ok(())
}

fn build<H: ClosureHeader>(
    history: &ClosureHistory<H>,
    approval: &impl ClosureApproval<H>,
    replay: bool,
) -> Result<ClosureFormationGraph, ClosureGraphError> {
    let acts: BTreeMap<_, _> = history.acts().iter().map(|act| (act.id(), act)).collect();
    let mut ordered: Vec<_> = history.acts().iter().collect();
    ordered.sort_by_key(|act| ((act.epoch(), act.position()), act.id()));
    let mut graph: FormationGraph = StableDiGraph::new();
    let mut nodes = BTreeMap::new();
    for act in ordered {
        let projections = checked_project(act, &acts, approval, replay)?;
        for (source, target, _) in &projections {
            for node in [source, target] {
                if let std::collections::btree_map::Entry::Vacant(entry) = nodes.entry(node.clone()) {
                    let index = graph.try_add_node(node.clone()).map_err(|_| ClosureGraphError::Capacity)?;
                    entry.insert(index);
                }
            }
        }
        for (source, target, projection) in projections {
            let source = *nodes.get(&source).ok_or(ClosureGraphError::Incidence)?;
            let target = *nodes.get(&target).ok_or(ClosureGraphError::Incidence)?;
            graph
                .try_add_edge(source, target, projection)
                .map_err(|_| ClosureGraphError::Capacity)?;
        }
    }
    Ok(ClosureFormationGraph(graph))
}

/// Reconstruct a strict whole-act graph using approval only.
/// # Errors
/// Refuses structure, approval, capacity and graph mismatch meanings.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "formation::closure::reconstruct"
    ),
    ret
)]
pub fn reconstruct<H: ClosureHeader>(
    history: &ClosureHistory<H>,
    approval: &impl ClosureApproval<H>,
) -> Result<ClosureFormationGraph, ClosureGraphError> {
    build(history, approval, false)
}

/// Reconstruct retained finalized public-parent faults without repairing them.
/// # Errors
/// Refuses structure, approval and capacity meanings.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "formation::closure::reconstruct_replay"
    ),
    ret
)]
pub fn reconstruct_replay<H: ClosureHeader>(
    history: &ClosureHistory<H>,
    approval: &impl ClosureApproval<H>,
) -> Result<ClosureFormationGraph, ClosureGraphError> {
    build(history, approval, true)
}

/// Compare a successor graph with strict reconstruction.
/// # Errors
/// Refuses reconstruction or any changed index, endpoint or weight.
#[tracing::instrument(
    name = "alg:design:formation",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:formation",
        source_item = "formation::closure::validate_formation"
    ),
    ret
)]
pub fn validate_formation<H: ClosureHeader>(
    graph: &ClosureFormationGraph,
    history: &ClosureHistory<H>,
    approval: &impl ClosureApproval<H>,
) -> Result<(), ClosureGraphError> {
    let expected = reconstruct(history, approval)?;
    let actual = graph.graph();
    let reference = expected.graph();
    if actual.node_count() != reference.node_count() || actual.edge_count() != reference.edge_count() {
        return Err(ClosureGraphError::GraphMismatch);
    }
    if reference
        .node_indices()
        .any(|index| actual.node_weight(index) != reference.node_weight(index))
    {
        return Err(ClosureGraphError::GraphMismatch);
    }
    if reference.edge_indices().any(|index| {
        actual.edge_weight(index) != reference.edge_weight(index)
            || actual.edge_endpoints(index) != reference.edge_endpoints(index)
    }) {
        return Err(ClosureGraphError::GraphMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pn_records::closure::{test_support, validate_history};
    use std::cell::RefCell;

    #[derive(Debug, Default)]
    struct Approval(RefCell<Vec<u64>>);

    impl ClosureApproval<test_support::FixtureHeader> for Approval {
        fn approval(&self, act: &ClosureAct<test_support::FixtureHeader>) -> bool {
            self.0.borrow_mut().push(act.id().sequence);
            true
        }
    }

    fn finite() -> ClosureHistory<test_support::FixtureHeader> {
        validate_history(vec![test_support::registration(1, 1), test_support::registration(2, 2)], &[]).unwrap()
    }

    /// Finite structural replay stays fixed while unrelated external holder observations vary.
    /// ´claim:formation:closure-reconstruction-holder-independent´
    /// ´test:unit:removal-independence´
    #[test]
    fn removal_independence() {
        let history = finite();
        let approval = Approval::default();
        let first = reconstruct(&history, &approval).unwrap();
        let mut holder_observations = BTreeMap::from([(history.acts()[0].id().clone(), true)]);
        holder_observations.insert(history.acts()[0].id().clone(), false);
        let second = reconstruct(&history, &approval).unwrap();
        assert_ne!(holder_observations.values().next().copied(), Some(true));
        assert_eq!(first.graph().node_count(), second.graph().node_count());
        assert_eq!(first.graph().edge_count(), second.graph().edge_count());
        assert!(validate_formation(&first, &history, &approval).is_ok());
        assert!(validate_formation(&second, &history, &approval).is_ok());
    }

    /// A concrete approval-only consumer reconstructs complete successor acts.
    /// ´claim:formation:closure-only-consumer´
    /// ´test:unit:closure-only-consumer´
    #[test]
    fn closure_only_consumer() {
        let history = finite();
        let approval = Approval::default();
        let graph = reconstruct(&history, &approval).unwrap();
        assert_eq!(*approval.0.borrow(), [1, 2]);
        assert_eq!(graph.graph().node_count(), 2);
        assert_eq!(graph.graph().edge_count(), 2);
        let replay = reconstruct_replay(&history, &Approval::default()).unwrap();
        assert_eq!(replay.graph().edge_count(), 2);
    }
}
