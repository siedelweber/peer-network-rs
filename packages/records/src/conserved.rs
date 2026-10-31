//! Ordered evidence for the frozen conserved map and its projected residual.
//! (´[ROOT-alg:design:residual]´)

use crate::{primitive::PrimitiveRecord, solve::Bounds};
use std::collections::BTreeMap;

/// A map's original point, ordered scalar premises and exact endpoint composition.
/// Work is the producer's consumption; replay measures its own independent consumption.
/// (´[ROOT-rule:design:evaluation-schedule]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRecord {
    pub edition: crate::DeclarationId,
    pub boundary: u64,
    pub point: BTreeMap<String, String>,
    pub rung: String,
    pub precision: u32,
    pub primitives: Vec<PrimitiveRecord>,
    pub image: BTreeMap<String, Bounds>,
    pub transport_input: crate::transport::TransportInput<nrz_cas::enclosure::Interval>,
    pub transport: crate::transport::TransportOutput<nrz_cas::enclosure::Interval>,
    pub work: u64,
    pub composition_work: u64,
}

/// The rational proposal prefix and final certified map remain separately accounted.
/// These carriers grant no authority until the frozen-package checker accepts them.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolveRecord {
    pub fence: crate::solve::Evidence,
    pub rounds: Vec<ResidualRound>,
    pub work: u64,
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
