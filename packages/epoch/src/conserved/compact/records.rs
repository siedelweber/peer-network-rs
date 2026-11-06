//! Ordered evidence for the frozen conserved map and its projected residual.
//! (´[ROOT-alg:design:residual]´)

use pn_records::{primitive::PrimitiveRecord, solve::Bounds};
use std::collections::BTreeMap;

/// A map's original point, ordered scalar premises and outward dyadic composition.
/// Work is the producer's consumption; replay measures its own independent consumption.
/// (´[ROOT-rule:design:evaluation-schedule]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRecord {
    pub edition: pn_records::DeclarationId,
    pub boundary: u64,
    pub point: BTreeMap<String, String>,
    pub rung: String,
    pub precision: u32,
    pub wall_enclosure: Option<pn_records::primitive::Range>,
    pub primitives: Vec<PrimitiveRecord>,
    pub image: BTreeMap<String, Bounds>,
    pub transport: pn_graph::transport::applied::Output,
    pub work: u64,
    pub composition_work: u64,
}

/// The rational proposal prefix and final certified map remain separately accounted.
/// These carriers grant no authority until the frozen-package checker accepts them.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolveRecord {
    pub fence: pn_records::solve::Evidence,
    pub rounds: Vec<ResidualRound>,
    pub work: u64,
    /// Actual cumulative Work charged to the mandatory solve replay budget.
    /// Fence validation retains its separate operation limits.
    pub replay_work: u64,
}

/// One declared precision's complete proposal prefix and residual construction.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidualRound {
    pub proposals: Vec<MapRecord>,
    pub certified: MapRecord,
    pub residual: String,
    pub contraction: String,
    pub radius: String,
    pub standing: BTreeMap<String, Bounds>,
    pub candidate_work: u64,
    pub work: u64,
}
