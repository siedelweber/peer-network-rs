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
    pub wall_enclosure: Option<crate::primitive::Range>,
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

/// Exact reference source parameters: rate = intercept + slope times the defining wall.
/// This verification carrier does not replace a frozen charged price.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationSource {
    pub name: String,
    pub count: String,
    pub intercept: String,
    pub slope: String,
}

/// A positive off-diagonal base score is the square root of this exact radicand.
/// (´[ROOT-alg:design:transport]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationEdge {
    pub source: String,
    pub target: String,
    pub radicand: String,
}

/// Separately declared full-emission verification map; all lists retain their input order.
/// The wall is a checked defining enclosure supplied by the owning composition.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationInput {
    pub sources: Vec<VerificationSource>,
    pub edges: Vec<VerificationEdge>,
    pub wall: crate::primitive::Range,
    pub shape: Vec<String>,
    pub depth_mass: Vec<String>,
    pub retention: String,
    pub strength: String,
    pub endpoint_bits: u32,
}

/// Independently reconstructed box map with its scalar evidence and charged composition.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxMapRecord {
    pub input: VerificationInput,
    pub coordinates: Vec<crate::primitive::Range>,
    pub image: Vec<crate::primitive::Range>,
    pub hull: Vec<crate::primitive::Range>,
    pub inner_hull: Vec<crate::primitive::Range>,
    pub singleton: Vec<bool>,
    pub fence: crate::primitive::Range,
    pub contraction: String,
    pub primitives: Vec<PrimitiveRecord>,
    pub work: u64,
}

/// Image-first residual bound around the exact y=F(z), with a distinct one-map comparison.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoMapRecord {
    pub first: BoxMapRecord,
    pub second: BoxMapRecord,
    pub one_map_radius: String,
    pub radius: String,
    pub enclosure: Vec<crate::primitive::Range>,
    pub assembly_work: u64,
}

/// Inflation and a separate measured allowance for a corroborating local check.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDeclaration {
    pub inflation: String,
    pub padding: String,
    pub maximum_work: u64,
}

/// A local inclusion never replaces the global residual certificate.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalVerdict {
    Included,
    Unresolved,
}

/// Reconstructible interval forward derivatives and the rational Krawczyk image.
/// The preconditioner is the declared identity, with denominator one.
/// (´[ROOT-alg:design:residual]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRecord {
    pub declaration: LocalDeclaration,
    pub active: Vec<usize>,
    pub center: Vec<crate::primitive::Range>,
    pub domain: Vec<crate::primitive::Range>,
    pub preconditioner: Vec<Vec<String>>,
    pub preconditioner_denominator: String,
    pub jacobian: Vec<Vec<crate::primitive::Range>>,
    pub asserted: Vec<crate::primitive::Range>,
    pub jacobian_norm: String,
    pub inflation_radius: String,
    pub image_radius: String,
    pub above_wall: bool,
    pub verdict: LocalVerdict,
    pub primitives: Vec<PrimitiveRecord>,
    pub work: u64,
}
