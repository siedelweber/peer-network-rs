//! Bounded activation revision three, retaining independent original-scope replay.
//! (´[ROOT-rule:design:evaluation-schedule]´)
mod driver;
mod fence;
mod map;
pub mod records;
mod residual;
use crate::solve::compact::BoundProcedure;
pub use driver::{Accounting, Record, replay, solve};
use pn_records::solve::Bounds;
use std::collections::BTreeMap;
fn hull(bound: &BoundProcedure<'_>) -> BTreeMap<String, Bounds> {
    bound
        .inputs()
        .0
        .view()
        .support
        .ranges
        .iter()
        .map(|(actor, r)| {
            (
                actor.clone(),
                Bounds {
                    lower: r.minimum.clone(),
                    upper: r.maximum.clone(),
                },
            )
        })
        .collect()
}

/// Required working grid; no implicit deployment precision is selected.
/// The original procedure's grid ceiling and end-to-end width remain binding.
/// (´[ROOT-rule:design:evaluation-schedule]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub working_precision: u32,
}
