//! Unserved node admission and bounded control execution boundary.
//!
//! (´def:node:scope´)

use async_graphql as _;
use async_graphql_derive as _;
use async_graphql_parser as _;
use async_graphql_value as _;
use pn_interchange as _;
use toml as _;
use tracing as _;

mod admission;
mod executor;
pub mod lifecycle;

pub use executor::{EntryError, ExecutionContext, execute};
