//! Unserved node admission boundary.
//!
//! (´def:node:scope´)

use async_graphql as _;
use async_graphql_derive as _;
use async_graphql_parser as _;
use async_graphql_value as _;
use pn_interchange as _;
use toml as _;
use tracing as _;

#[cfg(test)]
mod admission;
