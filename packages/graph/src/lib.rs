//! Whole-act dependency partition; family formation and geometry remain separate.
//! (´def:membership:partition´)

use std::collections::BTreeSet;

use petgraph::graph::UnGraph;
use pn_records::{ActId, BoundaryInputs};

/// Closure roots and the least shared identity witnessing each intersection.
/// This is a disposable acceleration graph, not a publication encoding.
/// (´def:membership:partition´)
pub type IntersectionGraph = UnGraph<ActId, ActId>;

/// Disjoint blocks of whole act identities, each in authoritative order.
/// (´def:membership:partition´)
pub type DependencyBlocks = Vec<Vec<ActId>>;

/// Refusal to publish an incomplete or inconsistent partition.
/// (´def:membership:partition´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PartitionError {
    /// The temporary backend cannot represent another vertex or edge.
    #[error("intersection graph capacity exhausted")]
    Capacity,
    /// The closure union or block multiplicity differs from the proposed set.
    #[error("partition does not cover the proposed act set exactly once")]
    Coverage,
}

/// Partition records' principal closures relative to their fixed history.
/// (´[ROOT-alg:design:dependency-partition]´)
///
/// The returned graph has roots in authoritative order and each intersecting
/// pair once in lexicographic position order. Each edge retains one least common
/// identity; full intersections remain recoverable from records' closures.
/// Blocks retain whole acts by identity and are ordered by their
/// earliest authoritative member; they may interleave. Neither graph mutation
/// nor serialization preserves this witness. No formation or marker verdict
/// follows from a records-level partition.
///
/// # Errors
/// Returns `Capacity` on backend index exhaustion, or `Coverage` rather than
/// publishing a missing, foreign or multiply counted member.
#[tracing::instrument(
    name = "alg:design:dependency-partition",
    fields(
        execution_owner = "GRAPH",
        claim_owner = "ROOT",
        claim_label = "alg:design:dependency-partition",
        source_item = "partition_dependencies"
    ),
    ret
)]
pub fn partition_dependencies(input: &BoundaryInputs<'_>) -> Result<(IntersectionGraph, DependencyBlocks), PartitionError> {
    let expected: BTreeSet<_> = input.acts().iter().map(|act| act.id().clone()).collect();
    let mut graph = IntersectionGraph::new_undirected();
    let mut closures = Vec::new();
    for act in input.acts() {
        let closure = input
            .closures()
            .iter()
            .find(|closure| closure.root() == act.id())
            .ok_or(PartitionError::Coverage)?;
        let members: BTreeSet<_> = closure.members().iter().cloned().collect();
        if !members.contains(act.id()) || !members.is_subset(&expected) {
            return Err(PartitionError::Coverage);
        }
        let node = graph.try_add_node(act.id().clone()).map_err(|_| PartitionError::Capacity)?;
        closures.push((node, members));
    }
    for (offset, (left, members)) in closures.iter().enumerate() {
        for (right, other) in closures.iter().skip(offset + 1) {
            if let Some(shared) = members.intersection(other).next() {
                graph
                    .try_add_edge(*left, *right, shared.clone())
                    .map_err(|_| PartitionError::Capacity)?;
            }
        }
    }
    let mut blocks = Vec::new();
    for component in petgraph::algo::kosaraju_scc(&graph) {
        let mut members = BTreeSet::new();
        for node in component {
            members.extend(closures[node.index()].1.iter().cloned());
        }
        let block = input
            .acts()
            .iter()
            .filter(|act| members.contains(act.id()))
            .map(|act| act.id().clone())
            .collect();
        blocks.push(block);
    }
    if !covers_once(&expected, &blocks) {
        return Err(PartitionError::Coverage);
    }
    blocks.sort_by_key(|block| input.acts().iter().position(|act| block.first() == Some(act.id())));
    Ok((graph, blocks))
}

fn covers_once(expected: &BTreeSet<ActId>, blocks: &[Vec<ActId>]) -> bool {
    let mut actual = BTreeSet::new();
    blocks
        .iter()
        .all(|block| !block.is_empty() && block.iter().all(|id| actual.insert(id.clone())))
        && actual == *expected
}

#[cfg(test)]
mod tests {
    use super::{ActId, BTreeSet, covers_once};

    /// Claim: The publication guard rejects omitted, foreign and repeated identities and empty blocks, while accepting an empty proposed set only as an empty partition, so a component computation cannot publish a partial or multiply counted union.
    /// ´claim:membership:partition-publication-requires-exact-cover´
    /// ´test:unit:publication-guard´
    #[test]
    fn publication_guard() {
        let id = ActId {
            author: "a".into(),
            sequence: 1,
            family: "fixture".into(),
        };
        let other = ActId {
            sequence: 2,
            ..id.clone()
        };
        let expected = BTreeSet::from([id.clone()]);
        assert!(covers_once(&expected, &[vec![id.clone()]]));
        assert!(!covers_once(&expected, &[]));
        assert!(!covers_once(&expected, &[vec![other]]));
        assert!(!covers_once(&expected, &[vec![id.clone(), id.clone()]]));
        assert!(!covers_once(&expected, &[vec![id.clone()], vec![id]]));
        assert!(!covers_once(&BTreeSet::new(), &[vec![]]));
        assert!(covers_once(&BTreeSet::new(), &[]));
    }
}
