//! Ownership transfer and explicit disposal for caller-reserved public values.
//! (´amend:interchange:canonical-budget´)

use super::{Array, Bytes, Map, Text, Value};
use std::mem;

/// A transfer refuses without moving, shrinking or copying its input buffer.
/// (´amend:interchange:canonical-budget´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// Exact payload storage requires length equal to capacity.
    SpareCapacity,
    /// Text must already be valid UTF-8.
    InvalidUtf8 {
        /// Byte offset at which valid UTF-8 ends.
        /// (´amend:interchange:canonical-budget´)
        offset: usize,
    },
    /// Only the position projection's empty map is admitted by this constructor.
    NonemptyMap,
}

impl Bytes {
    /// Transfer a fully occupied byte buffer, retaining its address and capacity.
    /// The documented equal-length/capacity vector-to-box guarantee excludes shrinking.
    /// (´amend:interchange:canonical-budget´)
    /// # Errors
    /// `SpareCapacity` leaves the original buffer untouched.
    pub fn take_reserved(buffer: &mut Vec<u8>) -> Result<Self, TransferError> {
        let scope = crate::observe::scope(
            "INTERCHANGE",
            "rule:observe:spans",
            "value::budget::Bytes::take_reserved",
            &buffer,
        );
        let result = if buffer.len() == buffer.capacity() {
            // Recollection or shrink would evade reservation-site controls; re-review this gate.
            Ok(Self(mem::take(buffer).into_boxed_slice()))
        } else {
            Err(TransferError::SpareCapacity)
        };
        scope.finish(&result);
        result
    }
}

impl Text {
    /// Transfer a fully occupied valid UTF-8 buffer without copying or shrinking.
    /// (´amend:interchange:canonical-budget´)
    /// # Errors
    /// Spare capacity or invalid UTF-8 leaves the buffer, address and capacity untouched.
    pub fn take_reserved(buffer: &mut Vec<u8>) -> Result<Self, TransferError> {
        let scope = crate::observe::scope(
            "INTERCHANGE",
            "rule:observe:spans",
            "value::budget::Text::take_reserved",
            &buffer,
        );
        let result = Self::transfer(buffer);
        scope.finish(&result);
        result
    }

    fn transfer(buffer: &mut Vec<u8>) -> Result<Self, TransferError> {
        if buffer.len() != buffer.capacity() {
            return Err(TransferError::SpareCapacity);
        }
        if let Err(error) = std::str::from_utf8(buffer) {
            return Err(TransferError::InvalidUtf8 {
                offset: error.valid_up_to(),
            });
        }
        // String::from_utf8 transfers the vector without copying; no box conversion occurs.
        // A copy or normalization here would evade reservation-site controls and needs re-review.
        match String::from_utf8(mem::take(buffer)) {
            Ok(text) => Ok(Self(text)),
            Err(error) => {
                let offset = error.utf8_error().valid_up_to();
                *buffer = error.into_bytes();
                Err(TransferError::InvalidUtf8 { offset })
            }
        }
    }
}

impl Array {
    /// Transfer an already reserved vector without collecting, shrinking or growing it.
    /// Elements already carry their value invariants; spare capacity is preserved.
    /// (´amend:interchange:canonical-budget´)
    #[must_use]
    pub fn take_reserved(buffer: &mut Vec<Value>) -> Self {
        let scope = crate::observe::scope(
            "INTERCHANGE",
            "rule:observe:spans",
            "value::budget::Array::take_reserved",
            &buffer,
        );
        // This is an ownership move, not a collection whose reuse is an optimization.
        let result = Self(mem::take(buffer));
        scope.finish(&result);
        result
    }
}

impl Map {
    /// Transfer an empty reserved map buffer without sorting or copying.
    /// Empty input establishes canonical order and distinctness without comparison scratch.
    /// (´amend:interchange:canonical-budget´)
    /// # Errors
    /// Nonempty input refuses unchanged; general map construction is outside this route.
    pub fn take_empty_reserved(buffer: &mut Vec<(Value, Value)>) -> Result<Self, TransferError> {
        let scope = crate::observe::scope(
            "INTERCHANGE",
            "rule:observe:spans",
            "value::budget::Map::take_empty_reserved",
            &buffer,
        );
        let result = if buffer.is_empty() {
            Ok(Self(mem::take(buffer)))
        } else {
            Err(TransferError::NonemptyMap)
        };
        scope.finish(&result);
        result
    }
}

impl Value {
    /// Consume a public value without allocating traversal storage or recursing.
    /// Vacated child slots temporarily hold parent links; ordinary `Drop` is unchanged.
    /// Observation is outside this guarantee. No callback is invoked during disposal.
    /// (´amend:interchange:canonical-budget´)
    pub fn dispose(self) {
        let scope = crate::observe::scope("INTERCHANGE", "rule:observe:spans", "value::budget::Value::dispose", &self);
        dismantle(self);
        scope.finish(&());
    }
}

fn dismantle(mut current: Value) {
    // This walk has no allocation site; added scratch can bypass site controls and needs re-review.
    let mut parent = Value::Null;
    loop {
        // A nonempty container lends its first child slot to the ancestor link.
        let slot = match &mut current {
            Value::Array(array) => array.0.first_mut(),
            Value::Map(map) => map.0.first_mut().map(|(key, _)| key),
            Value::Tag(tag) => Some(&mut *tag.item),
            _ => None,
        };
        if let Some(slot) = slot {
            mem::swap(slot, &mut parent);
            mem::swap(&mut current, &mut parent);
            continue;
        }
        drop(current);
        loop {
            let child = match &mut parent {
                Value::Array(array) if array.0.len() > 1 => array.0.pop(),
                Value::Map(map) if map.0.len() > 1 => match map.0.last_mut() {
                    Some((key, _)) if !matches!(key, Value::Null) => Some(mem::replace(key, Value::Null)),
                    _ => map.0.pop().map(|(_, value)| value),
                },
                Value::Map(map) => map.0.first_mut().and_then(|(_, value)| {
                    if matches!(value, Value::Null) {
                        None
                    } else {
                        Some(mem::replace(value, Value::Null))
                    }
                }),
                _ => None,
            };
            if let Some(child) = child {
                current = child;
                break;
            }
            let ancestor = match &mut parent {
                Value::Array(array) => array.0.pop(),
                Value::Map(map) => map.0.pop().map(|(key, _)| key),
                Value::Tag(tag) => Some(tag.take_item()),
                _ => None,
            };
            let Some(ancestor) = ancestor else {
                return;
            };
            // Emptied containers reach the unchanged destructor with no pending children.
            parent = ancestor;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn allocation_site() {
    tests::allocation_site();
}
