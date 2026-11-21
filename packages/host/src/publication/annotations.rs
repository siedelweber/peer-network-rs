//! Bounded traversal of an isolated canonical annotation map.
//! (´[ROOT-amend:design:implementation-annotations]´)

use pn_interchange::{CanonicalItem, CanonicalUsage, DecodeError, NamespaceLabel, Value};

/// Explicit trial ceilings; no field selects a publication profile.
#[derive(Clone, Copy, Debug)]
pub struct AnnotationLimits {
    /// Maximum complete encoded map bytes.
    pub map_bytes: usize,
    /// This consumer's available input-byte budget.
    pub caller_bytes: usize,
    /// Canonical walker's cumulative reservation ceiling.
    pub allocation_bytes: usize,
    /// This reader's cumulative namespace-name allocation budget.
    pub visitor_bytes: usize,
}

/// Counters retained even when validation refuses.
#[derive(Default, Debug)]
pub struct AnnotationUsage {
    /// Reservations made by the canonical walker.
    pub canonical: CanonicalUsage,
    /// Bytes admitted by the shared reservation callback.
    pub reserved_bytes: usize,
    /// Bytes admitted for transient namespace-name validation.
    pub visitor_bytes: usize,
    /// Completed canonical items observed by the reader.
    pub visited_items: usize,
}

/// The fragment's refusal classes, separate from core verification.
#[derive(Debug)]
pub enum AnnotationError {
    /// The complete map exceeds the supplied map allowance.
    AnnotationSize,
    /// This consumer's byte or allocation budget cannot complete the read.
    Unavailable,
    /// Canonical syntax or the annotation-map shape is invalid.
    Framing,
}

/// A validated borrowed map with no entry index or owned payload.
#[derive(Debug)]
pub struct AnnotationMap<'a> {
    bytes: &'a [u8],
}

impl AnnotationMap<'_> {
    /// The exact original canonical map bytes.
    #[must_use]
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "publication::annotations::AnnotationMap < '_ >::as_bytes"
        ),
        ret
    )]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

fn atom(name: &[u8]) -> bool {
    name.len() <= 255
        && name
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn visit(
    item: CanonicalItem<'_>,
    limits: AnnotationLimits,
    visitor_bytes: &mut usize,
    visited_items: &mut usize,
    state: &mut State,
) {
    *visited_items += 1;
    if state.error.is_some() {
        return;
    }
    let payload = &item.bytes[item.payload_offset..];
    let outcome = match item.depth {
        1 => {
            if item.major != 5 || !state.outer_key || state.namespaces != item.argument {
                Err(AnnotationError::Framing)
            } else {
                Ok(())
            }
        }
        2 if state.outer_key => {
            if item.major == 3 {
                let next = visitor_bytes.checked_add(payload.len());
                if next.is_none_or(|value| value > limits.visitor_bytes) {
                    Err(AnnotationError::Unavailable)
                } else if let Ok(name) = std::str::from_utf8(payload) {
                    *visitor_bytes = next.unwrap_or(0);
                    if NamespaceLabel::parse(name).is_err() {
                        Err(AnnotationError::Framing)
                    } else {
                        state.outer_key = false;
                        Ok(())
                    }
                } else {
                    Err(AnnotationError::Framing)
                }
            } else {
                Err(AnnotationError::Framing)
            }
        }
        2 => {
            if item.major != 5 || !state.inner_key || state.fields != item.argument {
                Err(AnnotationError::Framing)
            } else {
                state.outer_key = true;
                state.namespaces += 1;
                state.fields = 0;
                Ok(())
            }
        }
        3 if state.inner_key => {
            if item.major != 3 || !atom(payload) {
                Err(AnnotationError::Framing)
            } else {
                state.inner_key = false;
                Ok(())
            }
        }
        3 => {
            if item.major == 2 {
                state.inner_key = true;
                state.fields += 1;
                Ok(())
            } else {
                Err(AnnotationError::Framing)
            }
        }
        _ => Err(AnnotationError::Framing),
    };
    if let Err(error) = outcome {
        state.error = Some(error);
    }
}

#[derive(Default)]
struct State {
    error: Option<AnnotationError>,
    outer_key: bool,
    inner_key: bool,
    namespaces: u64,
    fields: u64,
}

/// Validate a complete isolated annotation map without decoding opaque values.
///
/// # Errors
/// Refuses an oversized map before any walk, resource exhaustion as unavailable,
/// and noncanonical or incorrectly framed maps as framing errors.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "publication::annotations::read_annotation_map"
    ),
    ret
)]
pub fn read_annotation_map<'a>(
    annotation_map_bytes: &'a [u8],
    limits: AnnotationLimits,
    usage: &mut AnnotationUsage,
) -> Result<AnnotationMap<'a>, AnnotationError> {
    *usage = AnnotationUsage::default();
    if annotation_map_bytes.len() > limits.map_bytes {
        return Err(AnnotationError::AnnotationSize);
    }
    if annotation_map_bytes.len() > limits.caller_bytes {
        return Err(AnnotationError::Unavailable);
    }
    let mut state = State {
        outer_key: true,
        inner_key: true,
        ..State::default()
    };
    let AnnotationUsage {
        canonical,
        reserved_bytes,
        visitor_bytes,
        visited_items,
    } = usage;
    Value::validate_canonical_bytes(
        annotation_map_bytes,
        limits.allocation_bytes,
        canonical,
        |amount| {
            let next = reserved_bytes.checked_add(amount).ok_or(())?;
            if next > limits.allocation_bytes {
                return Err(());
            }
            *reserved_bytes = next;
            Ok(())
        },
        |item| visit(item, limits, visitor_bytes, visited_items, &mut state),
    )
    .map_err(|error| match error {
        DecodeError::CanonicalLimit { .. }
        | DecodeError::CanonicalReservation { .. }
        | DecodeError::CanonicalAllocation { .. } => AnnotationError::Unavailable,
        _ => AnnotationError::Framing,
    })?;
    if let Some(error) = state.error {
        return Err(error);
    }
    Ok(AnnotationMap {
        bytes: annotation_map_bytes,
    })
}

/// Validate and skip a complete opaque annotation map.
///
/// # Errors
/// Returns the same size, budget and framing refusals as `read_annotation_map`.
#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "publication::annotations::skip_annotation_map"
    ),
    ret
)]
pub fn skip_annotation_map(
    annotation_map_bytes: &[u8],
    limits: AnnotationLimits,
    usage: &mut AnnotationUsage,
) -> Result<(), AnnotationError> {
    read_annotation_map(annotation_map_bytes, limits, usage).map(|_| ())
}
