//! mod:module:decode
//!
//! The validating decoder — refuses everything outside the data language.
//!
//! One pass checks everything membership requires: preferred
//! serialization at every head, no indefinite-length item of any major
//! type, map keys sorted bytewise-lexicographically on their encoded forms
//! and pairwise distinct, floating-point values in shortest form, text
//! strings valid UTF-8, and no trailing bytes after the single item.
//!
//! Sortedness and distinctness cost one comparison per entry rather than
//! one encoding: the decoder retains the byte range of each key it decodes
//! and compares adjacent ranges in the input it already holds.
//!
//! Nesting is bounded by the length of the input and by nothing else, so
//! the walk is iterative — an explicit stack of frames, never the call
//! stack.

use std::cmp::Ordering;

use crate::encode::initial_byte;
use crate::error::DecodeError;
use crate::value::{Array, Bytes, Float, FloatWidth, Map, Negative, Simple, Tag, Text, Value, bits_to_f64};

/// A container whose head has been read and whose items have not.
///
/// `start` is where the container's own head began, which becomes the
/// start of the finished value — the byte range a map needs to compare its
/// keys by.
#[derive(Debug)]
enum Frame {
    Array {
        items: Vec<Value>,
        remaining: usize,
        indefinite: bool,
        start: usize,
    },
    Map {
        entries: Vec<(Value, Value)>,
        remaining: usize,
        indefinite: bool,
        pending_key: Option<Value>,
        previous_key: Option<(usize, usize)>,
        start: usize,
    },
    Tag {
        number: u64,
        start: usize,
    },
}

/// The declared count of a container is attacker-controlled, so it never
/// sizes an allocation on its own. Growth from a small capacity is
/// amortized constant, where trusting the count is a memory-exhaustion
/// primitive costing the attacker nine bytes.
const CONTAINER_CAPACITY_BOUND: u64 = 4;

/// Decoder reservations made by strict borrowed validation, including on refusal.
/// Observation and allocations made by the caller's visitor are outside these counters.
/// (´amend:interchange:canonical-budget´)
#[derive(Default, Debug)]
pub struct CanonicalUsage {
    /// Number of actual reservation requests.
    pub allocation_calls: usize,
    /// Cumulative requested bytes, including complete replacement capacities.
    pub allocation_bytes: usize,
}

/// A completed canonical item's borrowed encoding and already checked head.
/// Events are provisional until the entire validation call succeeds.
/// Major type, argument and payload offset use the CBOR head vocabulary;
/// the payload includes child encodings for containers and tags.
/// (´amend:interchange:canonical-budget´)
#[derive(Clone, Copy, Debug)]
pub struct CanonicalItem<'a> {
    /// Complete original item bytes, with no repaired or re-encoded spelling.
    pub bytes: &'a [u8],
    /// Item head offset in the original input.
    pub offset: usize,
    /// Root is depth one; completion events visit children before parents.
    pub depth: usize,
    /// Checked CBOR major type.
    pub major: u8,
    /// Checked head argument (including a tag number or container length).
    pub argument: u64,
    /// Byte offset of the payload within this item's encoding.
    pub payload_offset: usize,
}

/// Mandatory caller declarations for one transient API message.
///
/// There is no production default. Bytes count received input and cumulative
/// allocation requests separately; items include string chunks. Depth counts
/// value and chunk heads from one at the root; nesting counts active containers and chunked
/// strings. Work counts inspected/copied bytes, heads and map insertion work.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    /// Maximum received bytes, checked before parsing.
    pub input_bytes: usize,
    /// Maximum cumulative bytes requested by decoder buffer reservations.
    pub allocation_bytes: usize,
    /// Maximum value and chunk heads.
    pub items: usize,
    /// Maximum value or chunk-head depth, with the root at one.
    pub depth: usize,
    /// Maximum simultaneously open containers, including chunked strings.
    pub nesting: usize,
    /// Maximum deterministic decoding work units.
    pub work: usize,
}

/// Decoder-owned reservation counters, retained on success and refusal.
///
/// These count actual calls at the decoder's buffer reservation boundary, not
/// allocator metadata, tracing subscribers or subsequent consumer operations.
#[derive(Default, Debug)]
pub struct TransportUsage {
    /// Number of buffer reservation calls actually made.
    pub allocation_calls: usize,
    /// Cumulative requested buffer bytes, including replacement buffers.
    pub allocation_bytes: usize,
    /// Value and chunk heads charged.
    pub items: usize,
    /// Work units charged.
    pub work: usize,
}

/// Owned canonical decoding and borrowed validation share the strict grammar.
/// Transport cannot change either route's canonical acceptance.
enum ReadPolicy<'a> {
    Strict,
    Validate {
        allocation_bytes: usize,
        usage: &'a mut CanonicalUsage,
        reservation: &'a mut dyn FnMut(usize) -> Result<(), ()>,
        visitor: &'a mut dyn FnMut(CanonicalItem<'_>),
    },
    Transport {
        limits: TransportLimits,
        usage: &'a mut TransportUsage,
    },
}

impl ReadPolicy<'_> {
    fn tagged(&self, number: u64, value: Value) -> Value {
        // Reviewed validation property: no owned tag box; see read_item's review boundary.
        if self.validation() {
            Value::Null
        } else {
            Value::Tag(Tag::new(number, value))
        }
    }

    fn map_entry(
        &mut self,
        entries: &mut Vec<(Value, Value)>,
        pair: (Value, Value),
        remaining: Option<usize>,
        index: usize,
        offset: usize,
    ) -> Result<(), DecodeError> {
        if self.validation() {
            // Reviewed validation property: no entry buffer growth; re-review changes here.
            return Ok(());
        }
        self.reserve(entries, 1, remaining, offset)?;
        if self.transport() {
            entries.insert(index, pair);
        } else {
            entries.push(pair);
        }
        Ok(())
    }

    fn key_position(
        &mut self,
        entries: &[(Value, Value)],
        value: &Value,
        start: usize,
        end: usize,
    ) -> Result<(usize, usize), DecodeError> {
        if self.transport() {
            Ok((transport_key_position(entries, value, self, start)?, 0))
        } else {
            Ok((start, end))
        }
    }

    fn array(&self, items: Vec<Value>) -> Value {
        // Reviewed validation property: no owned finalization; re-review changes here.
        if self.validation() {
            return Value::Null;
        }
        Value::Array(if self.transport() {
            Array::from_decoded(items)
        } else {
            Array::new(items)
        })
    }

    fn map(&self, entries: Vec<(Value, Value)>) -> Value {
        // Reviewed validation property: no owned finalization; re-review changes here.
        if self.validation() {
            return Value::Null;
        }
        Value::Map(if self.transport() {
            Map::from_transport(entries)
        } else {
            Map::from_sorted(entries)
        })
    }
    fn transport(&self) -> bool {
        matches!(self, Self::Transport { .. })
    }

    fn validation(&self) -> bool {
        matches!(self, Self::Validate { .. })
    }

    fn completed(&mut self, input: &[u8], start: usize, end: usize, depth: usize) -> Result<(), DecodeError> {
        if let Self::Validate { visitor, .. } = self {
            // Reuse the strict head reader; this does not walk or allocate a value.
            let mut payload = start;
            let head = read_head(input, &mut payload)?;
            visitor(CanonicalItem {
                bytes: &input[start..end],
                offset: start,
                depth,
                major: head.major,
                argument: head.argument,
                payload_offset: payload - start,
            });
        }
        Ok(())
    }

    fn limit(value: usize, limit: usize, resource: &'static str, offset: usize) -> Result<(), DecodeError> {
        if value > limit {
            return Err(DecodeError::TransportLimit { resource, limit, offset });
        }
        Ok(())
    }

    fn add(value: &mut usize, amount: usize, limit: usize, resource: &'static str, offset: usize) -> Result<(), DecodeError> {
        let next = value
            .checked_add(amount)
            .ok_or(DecodeError::TransportLimit { resource, limit, offset })?;
        Self::limit(next, limit, resource, offset)?;
        *value = next;
        Ok(())
    }

    fn work(&mut self, amount: usize, offset: usize) -> Result<(), DecodeError> {
        if let Self::Transport { limits, usage } = self {
            Self::add(&mut usage.work, amount, limits.work, "work", offset)?;
        }
        Ok(())
    }

    fn item(&mut self, depth: usize, offset: usize) -> Result<(), DecodeError> {
        if let Self::Transport { limits, usage } = self {
            Self::limit(depth, limits.depth, "depth", offset)?;
            Self::add(&mut usage.items, 1, limits.items, "items", offset)?;
        }
        self.work(1, offset)
    }

    fn container(&self, count: u64, nesting: usize, offset: usize) -> Result<(), DecodeError> {
        if let Self::Transport { limits, usage } = self {
            Self::limit(nesting, limits.nesting, "nesting", offset)?;
            if count > (limits.items - usage.items) as u64 {
                return Err(DecodeError::TransportLimit {
                    resource: "items",
                    limit: limits.items,
                    offset,
                });
            }
        }
        Ok(())
    }

    fn reserve<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
        remaining: Option<usize>,
        offset: usize,
    ) -> Result<(), DecodeError> {
        let Some(length) = values.len().checked_add(additional) else {
            return Err(DecodeError::TransportAllocation { offset });
        };
        if length <= values.capacity() {
            return Ok(());
        }
        if let Self::Validate {
            allocation_bytes,
            usage,
            reservation,
            ..
        } = self
        {
            let capacity = values.capacity().saturating_mul(2).max(length);
            let amount = capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(DecodeError::CanonicalLimit {
                    limit: *allocation_bytes,
                    offset,
                })?;
            let next = usage
                .allocation_bytes
                .checked_add(amount)
                .ok_or(DecodeError::CanonicalLimit {
                    limit: *allocation_bytes,
                    offset,
                })?;
            if next > *allocation_bytes {
                return Err(DecodeError::CanonicalLimit {
                    limit: *allocation_bytes,
                    offset,
                });
            }
            reservation(amount).map_err(|()| DecodeError::CanonicalReservation { offset })?;
            usage.allocation_bytes = next;
            usage.allocation_calls += 1;
            return validation_reserve(values, capacity, usage, offset);
        }
        self.work(values.len(), offset)?;
        if let Self::Transport { limits, usage } = self {
            // Doubling amortizes relocation without trusting a declared count
            // as an initial allocation. A definite container caps spare capacity.
            let capacity = values
                .capacity()
                .saturating_mul(2)
                .max(length)
                .min(remaining.map_or(usize::MAX, |count| values.len().saturating_add(count)));
            let amount = capacity
                .checked_mul(std::mem::size_of::<T>())
                .ok_or(DecodeError::TransportLimit {
                    resource: "allocation bytes",
                    limit: limits.allocation_bytes,
                    offset,
                })?;
            Self::add(
                &mut usage.allocation_bytes,
                amount,
                limits.allocation_bytes,
                "allocation bytes",
                offset,
            )?;
            usage.allocation_calls += 1;
            values
                .try_reserve_exact(capacity - values.len())
                .map_err(|_| DecodeError::TransportAllocation { offset })?;
        } else {
            values.reserve(additional);
        }
        Ok(())
    }

    fn boxed(&mut self, bytes: Vec<u8>, offset: usize) -> Result<Box<[u8]>, DecodeError> {
        if bytes.capacity() != bytes.len()
            && let Self::Transport { limits, usage } = self
        {
            Self::add(
                &mut usage.allocation_bytes,
                bytes.len(),
                limits.allocation_bytes,
                "allocation bytes",
                offset,
            )?;
            usage.allocation_calls += 1;
        }
        Ok(bytes.into_boxed_slice())
    }
}

impl Value {
    /// Validate strict canonical membership without constructing an owned value.
    /// The caller supplies the complete allocation ceiling; there is no default.
    /// Usage is reset at entry and retained on success and refusal. The only
    /// reservations are the iterative frame stack; content and item events borrow
    /// the input. The visitor must budget its own allocations and must not treat
    /// provisional events as evidence of complete membership.
    /// Each reservation requires both the ceiling and `reservation` to admit
    /// its exact requested bytes before charging usage and executing the request.
    /// A callback refusal retains usage for previously admitted requests only.
    /// (´amend:interchange:canonical-budget´)
    /// # Errors
    /// Retains strict syntax refusal classes; budget refusals are `CanonicalLimit`
    /// for the ceiling, `CanonicalReservation` for the caller's refusal, and
    /// `CanonicalAllocation` for a failed admitted allocator request.
    /// # Panics
    /// A panicking callback propagates with usage at the earlier admitted requests.
    pub fn validate_canonical_bytes(
        bytes: &[u8],
        allocation_bytes: usize,
        usage: &mut CanonicalUsage,
        mut reservation: impl FnMut(usize) -> Result<(), ()>,
        mut visitor: impl FnMut(CanonicalItem<'_>),
    ) -> Result<(), DecodeError> {
        let scope = crate::observe::scope(
            "INTERCHANGE",
            "rule:observe:spans",
            "decode::Value::validate_canonical_bytes",
            &(
                bytes,
                allocation_bytes,
                "reservation and item callbacks consume public input; executable capabilities",
            ),
        );
        *usage = CanonicalUsage::default();
        let result = (|| {
            let mut policy = ReadPolicy::Validate {
                allocation_bytes,
                usage,
                reservation: &mut reservation,
                visitor: &mut visitor,
            };
            let (_, consumed) = decode_one(bytes, &mut policy)?;
            if consumed != bytes.len() {
                return Err(DecodeError::TrailingBytes {
                    offset: consumed,
                    count: bytes.len() - consumed,
                });
            }
            Ok(())
        })();
        tracing::event!(tracing::Level::TRACE, canonical_usage = ?usage);
        let result = result.inspect_err(|_| tracing::event!(tracing::Level::TRACE, outcome = "refusal"));
        scope.finish(&result);
        result
    }
    /// Decode a bounded transient API value, never a canonical document.
    ///
    /// The caller supplies every ceiling; `usage` is reset for this invocation
    /// and remains available on refusal. Embedded byte strings are not decoded
    /// or repaired. Their consumer must validate those original bytes strictly.
    ///
    /// # Errors
    /// Refuses malformed CBOR, values outside the API vocabulary, duplicate
    /// text keys, trailing bytes, exhausted declarations or failed allocations.
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "decode::Value::from_transport_bytes"
        ),
        ret
    )]
    pub fn from_transport_bytes(bytes: &[u8], limits: TransportLimits, usage: &mut TransportUsage) -> Result<Value, DecodeError> {
        *usage = TransportUsage::default();
        let result = (|| {
            ReadPolicy::limit(bytes.len(), limits.input_bytes, "input bytes", 0)?;
            let mut policy = ReadPolicy::Transport { limits, usage };
            let (value, consumed) = decode_one(bytes, &mut policy)?;
            if consumed != bytes.len() {
                return Err(DecodeError::TrailingBytes {
                    offset: consumed,
                    count: bytes.len() - consumed,
                });
            }
            Ok(value)
        })();
        tracing::event!(tracing::Level::TRACE, transport_usage = ?usage);
        result.inspect_err(|_| {
            tracing::event!(tracing::Level::TRACE, outcome = "refusal");
        })
    }
    /// Decode one canonical name; trailing bytes are an error.
    ///
    /// ```
    /// use pn_interchange::{DecodeError, Value};
    ///
    /// assert_eq!(Value::from_canonical_bytes(&[0x01]).expect("canonical"), Value::Unsigned(1));
    ///
    /// let err = Value::from_canonical_bytes(&[0x01, 0x02]).expect_err("a second item");
    /// assert!(matches!(err, DecodeError::TrailingBytes { offset: 1, count: 1 }));
    /// ```
    ///
    /// # Errors
    /// Returns a decode error for malformed, noncanonical, truncated or trailing input.
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "decode::Value::from_canonical_bytes"
        ),
        ret
    )]
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Value, DecodeError> {
        let (value, consumed) = Value::from_canonical_prefix(bytes).inspect_err(|_| {
            tracing::event!(tracing::Level::TRACE, outcome = "refusal");
        })?;
        if consumed != bytes.len() {
            tracing::event!(tracing::Level::TRACE, outcome = "refusal");
            return Err(DecodeError::TrailingBytes {
                offset: consumed,
                count: bytes.len() - consumed,
            });
        }
        Ok(value)
    }

    /// Decode one canonical name from the head, returning the bytes
    /// consumed.
    ///
    /// ```
    /// use pn_interchange::Value;
    ///
    /// let (value, consumed) = Value::from_canonical_prefix(&[0x01, 0x02]).expect("one item");
    /// assert_eq!((value, consumed), (Value::Unsigned(1), 1));
    /// ```
    ///
    /// # Errors
    /// Returns a decode error if the first item is malformed, noncanonical or truncated.
    #[tracing::instrument(
        name = "rule:observe:spans",
        fields(
            execution_owner = "INTERCHANGE",
            claim_owner = "ROOT",
            claim_label = "rule:observe:spans",
            source_item = "decode::Value::from_canonical_prefix"
        ),
        ret
    )]
    pub fn from_canonical_prefix(bytes: &[u8]) -> Result<(Value, usize), DecodeError> {
        decode_one(bytes, &mut ReadPolicy::Strict).inspect_err(|_| {
            tracing::event!(tracing::Level::TRACE, outcome = "refusal");
        })
    }
}

fn validation_reserve<T>(values: &mut Vec<T>, capacity: usize, usage: &CanonicalUsage, offset: usize) -> Result<(), DecodeError> {
    // This observes this reservation site, not allocations that bypass it.
    #[cfg(test)]
    budget_tests::requested(capacity * std::mem::size_of::<T>(), usage);
    let _ = usage;
    values
        .try_reserve_exact(capacity - values.len())
        .map_err(|_| DecodeError::CanonicalAllocation { offset })
}

fn decode_one(input: &[u8], policy: &mut ReadPolicy<'_>) -> Result<(Value, usize), DecodeError> {
    let mut position = 0usize;
    let mut stack: Vec<Frame> = Vec::new();

    'item: loop {
        let start = position;
        let next = read_next(input, &mut position, &mut stack, policy)?;
        let (mut value, mut value_start) = match next {
            Item::Complete(value) => (value, start),
            Item::CompleteAt(value, start) => (value, start),
            Item::Container(frame) => {
                policy.reserve(&mut stack, 1, None, start)?;
                stack.push(frame);
                continue 'item;
            }
        };

        loop {
            policy.completed(input, value_start, position, stack.len() + 1)?;
            let Some(frame) = stack.pop() else {
                return Ok((value, position));
            };
            match frame {
                Frame::Tag { number, start } => {
                    value = policy.tagged(number, value);
                    value_start = start;
                }
                Frame::Array {
                    mut items,
                    remaining,
                    indefinite,
                    start,
                } => {
                    if !policy.validation() {
                        policy.reserve(&mut items, 1, (!indefinite).then_some(remaining), value_start)?;
                        items.push(value);
                    }
                    let remaining = if indefinite { remaining } else { remaining - 1 };
                    if !indefinite && remaining == 0 {
                        value = policy.array(items);
                        value_start = start;
                    } else {
                        stack.push(Frame::Array {
                            items,
                            remaining,
                            indefinite,
                            start,
                        });
                        continue 'item;
                    }
                }
                Frame::Map {
                    mut entries,
                    remaining,
                    indefinite,
                    pending_key,
                    previous_key,
                    start,
                } => match pending_key {
                    None => {
                        let next_key = Some(policy.key_position(&entries, &value, value_start, position)?);
                        if !policy.transport() {
                            strict_key_order(input, previous_key, value_start, position)?;
                        }
                        stack.push(Frame::Map {
                            entries,
                            remaining,
                            indefinite,
                            pending_key: Some(value),
                            previous_key: next_key,
                            start,
                        });
                        continue 'item;
                    }
                    Some(key) => {
                        policy.map_entry(
                            &mut entries,
                            (key, value),
                            (!indefinite).then_some(remaining),
                            previous_key.map_or(0, |(index, _)| index),
                            value_start,
                        )?;
                        let remaining = if indefinite { remaining } else { remaining - 1 };
                        if !indefinite && remaining == 0 {
                            value = policy.map(entries);
                            value_start = start;
                        } else {
                            stack.push(Frame::Map {
                                entries,
                                remaining,
                                indefinite,
                                pending_key: None,
                                previous_key,
                                start,
                            });
                            continue 'item;
                        }
                    }
                },
            }
        }
    }
}

fn strict_key_order(input: &[u8], previous: Option<(usize, usize)>, start: usize, end: usize) -> Result<(), DecodeError> {
    if let Some((from, to)) = previous {
        match input[from..to].cmp(&input[start..end]) {
            Ordering::Less => {}
            Ordering::Equal => return Err(DecodeError::DuplicateMapKey { offset: start }),
            Ordering::Greater => return Err(DecodeError::UnsortedMapKeys { offset: start }),
        }
    }
    Ok(())
}

fn read_next(
    input: &[u8],
    position: &mut usize,
    stack: &mut Vec<Frame>,
    policy: &mut ReadPolicy<'_>,
) -> Result<Item, DecodeError> {
    let closing = policy.transport()
        && input.get(*position) == Some(&0xff)
        && matches!(
            stack.last(),
            Some(Frame::Array { indefinite: true, .. } | Frame::Map { indefinite: true, .. })
        );
    Ok(if closing {
        policy.work(1, *position)?;
        *position += 1;
        match stack.pop() {
            Some(Frame::Array { items, start, .. }) => Item::CompleteAt(Value::Array(Array::from_decoded(items)), start),
            Some(Frame::Map {
                entries,
                pending_key: None,
                start,
                ..
            }) => Item::CompleteAt(Value::Map(Map::from_transport(entries)), start),
            _ => return Err(DecodeError::IllFormed { offset: *position - 1 }),
        }
    } else {
        policy.item(stack.len() + 1, *position)?;
        read_item(input, position, policy, stack.len())?
    })
}

fn transport_key_position(
    entries: &[(Value, Value)],
    key: &Value,
    policy: &mut ReadPolicy<'_>,
    offset: usize,
) -> Result<usize, DecodeError> {
    let Value::Text(key) = key else {
        return Err(DecodeError::TransportValue { offset });
    };
    let key = key.as_str();
    for (index, (existing, _)) in entries.iter().enumerate() {
        let Value::Text(existing) = existing else {
            return Err(DecodeError::TransportValue { offset });
        };
        let existing = existing.as_str();
        policy.work(key.len().min(existing.len()).saturating_add(1), offset)?;
        match existing.len().cmp(&key.len()).then_with(|| existing.cmp(key)) {
            Ordering::Equal => return Err(DecodeError::DuplicateMapKey { offset }),
            Ordering::Greater => {
                policy.work(entries.len() - index, offset)?;
                return Ok(index);
            }
            Ordering::Less => {}
        }
    }
    Ok(entries.len())
}

enum Item {
    Complete(Value),
    CompleteAt(Value, usize),
    Container(Frame),
}

fn read_transport_string(
    input: &[u8],
    position: &mut usize,
    head: &Head,
    policy: &mut ReadPolicy<'_>,
    nesting: usize,
    start: usize,
) -> Result<Value, DecodeError> {
    let mut bytes = Vec::new();
    if head.additional == 31 {
        policy.container(0, nesting + 1, start)?;
        loop {
            if input.get(*position) == Some(&0xff) {
                policy.work(1, *position)?;
                *position += 1;
                break;
            }
            let chunk_start = *position;
            policy.item(nesting + 2, chunk_start)?;
            let chunk = read_head_policy(input, position, policy)?;
            if chunk.major != head.major || chunk.additional == 31 {
                return Err(DecodeError::IllFormed { offset: chunk_start });
            }
            append_payload(input, position, chunk.argument, head.major, &mut bytes, policy)?;
        }
    } else {
        append_payload(input, position, head.argument, head.major, &mut bytes, policy)?;
    }
    if head.major == 3 {
        policy.work(bytes.len(), start)?;
    }
    let bytes = policy.boxed(bytes, start)?;
    if head.major == 2 {
        return Ok(Value::Bytes(Bytes::from_decoded(bytes)));
    }
    let text = String::from_utf8(bytes.into_vec()).map_err(|error| DecodeError::InvalidUtf8 {
        offset: start + error.utf8_error().valid_up_to(),
    })?;
    Ok(Value::Text(Text::from_decoded(text.into_boxed_str())))
}

fn append_payload(
    input: &[u8],
    position: &mut usize,
    length: u64,
    major: u8,
    bytes: &mut Vec<u8>,
    policy: &mut ReadPolicy<'_>,
) -> Result<(), DecodeError> {
    let offset = *position;
    let payload = read_payload(input, position, length)?;
    policy.work(payload.len(), offset)?;
    if major == 3 {
        std::str::from_utf8(payload).map_err(|error| DecodeError::InvalidUtf8 {
            offset: offset + error.valid_up_to(),
        })?;
    }
    policy.work(payload.len(), offset)?;
    policy.reserve(bytes, payload.len(), None, offset)?;
    bytes.extend_from_slice(payload);
    Ok(())
}

/// One item, complete or the head of a container.
///
/// A container's declared count is checked against the bytes that remain
/// before any capacity is reserved for it: an array item is at least one byte
/// and a map entry at least two, one for each half, so a count exceeding that
/// bound cannot be met however the rest is spelled.
// Justified: the initial capacity bound is four and fits every supported pointer width.
#[allow(clippy::cast_possible_truncation)]
fn read_item(input: &[u8], position: &mut usize, policy: &mut ReadPolicy<'_>, nesting: usize) -> Result<Item, DecodeError> {
    // Reviewed property: validation bypasses payload copies and owned containers.
    // A payload copy reintroduced here would pass every reservation-site control;
    // changes to these gates, tagged, array, map or map_entry require re-review.
    let start = *position;
    let head = read_head_policy(input, position, policy)?;
    let Head {
        major,
        additional,
        argument,
    } = head;

    let item = match major {
        0 => Item::Complete(Value::Unsigned(argument)),
        1 => Item::Complete(Value::Negative(Negative::from_argument(argument))),
        2 | 3 if policy.transport() => Item::Complete(read_transport_string(input, position, &head, policy, nesting, start)?),
        2 => {
            let payload = read_payload(input, position, argument)?;
            Item::Complete(if policy.validation() {
                Value::Null
            } else {
                Value::Bytes(Bytes::from(payload.to_vec()))
            })
        }
        3 => {
            let payload_start = *position;
            let payload = read_payload(input, position, argument)?;
            match std::str::from_utf8(payload) {
                Ok(text) => Item::Complete(if policy.validation() {
                    Value::Null
                } else {
                    Value::Text(Text::from(text.to_owned()))
                }),
                Err(e) => {
                    return Err(DecodeError::InvalidUtf8 {
                        offset: payload_start + e.valid_up_to(),
                    });
                }
            }
        }
        4 => {
            let indefinite = additional == 31;
            policy.container(if indefinite { 0 } else { argument }, nesting + 1, start)?;
            if !indefinite && argument > remaining_bytes(input, *position) {
                return Err(DecodeError::Truncated { offset: input.len() });
            }
            match usize::try_from(argument) {
                Ok(0) if !indefinite => Item::Complete(if policy.validation() {
                    Value::Null
                } else {
                    Value::Array(Array::new([]))
                }),
                Ok(count) => Item::Container(Frame::Array {
                    items: if policy.transport() || policy.validation() {
                        Vec::new()
                    } else {
                        Vec::with_capacity(count.min(CONTAINER_CAPACITY_BOUND as usize))
                    },
                    remaining: count,
                    indefinite,
                    start,
                }),
                Err(_) => {
                    return Err(DecodeError::Truncated { offset: input.len() });
                }
            }
        }
        5 => {
            let indefinite = additional == 31;
            policy.container(if indefinite { 0 } else { argument.saturating_mul(2) }, nesting + 1, start)?;
            if !indefinite && argument > remaining_bytes(input, *position) / 2 {
                return Err(DecodeError::Truncated { offset: input.len() });
            }
            match usize::try_from(argument) {
                Ok(0) if !indefinite => Item::Complete(if policy.validation() {
                    Value::Null
                } else {
                    Value::Map(Map::from_sorted(Vec::new()))
                }),
                Ok(count) => Item::Container(Frame::Map {
                    entries: if policy.transport() || policy.validation() {
                        Vec::new()
                    } else {
                        Vec::with_capacity(count.min(CONTAINER_CAPACITY_BOUND as usize))
                    },
                    remaining: count,
                    indefinite,
                    pending_key: None,
                    previous_key: None,
                    start,
                }),
                Err(_) => {
                    return Err(DecodeError::Truncated { offset: input.len() });
                }
            }
        }
        6 if policy.transport() => return Err(DecodeError::TransportValue { offset: start }),
        6 => Item::Container(Frame::Tag { number: argument, start }),
        _ => Item::Complete(read_major_seven(additional, argument, start, policy.transport())?),
    };
    Ok(item)
}

/// The values of major type 7: the booleans, null, the simple values, and the
/// floats.
///
/// A two-byte simple value whose second byte is below 0x20 is not well-formed
/// (RFC 8949 §3.3), the one-byte form being the only spelling of those values.
// Justified: the simple-value branch admits only an eight-bit argument from the validated CBOR head.
#[allow(clippy::cast_possible_truncation)]
fn read_major_seven(additional: u8, argument: u64, start: usize, transport: bool) -> Result<Value, DecodeError> {
    match additional {
        20 => Ok(Value::Bool(false)),
        21 => Ok(Value::Bool(true)),
        22 => Ok(Value::Null),
        24 if argument < 32 => Err(DecodeError::IllFormed { offset: start }),
        0..=19 | 23 | 24 if transport => Err(DecodeError::TransportValue { offset: start }),
        0..=19 | 23 => Simple::new(additional)
            .map(Value::Simple)
            .map_err(|_| DecodeError::IllFormed { offset: start }),
        24 => {
            if argument < 32 {
                return Err(DecodeError::IllFormed { offset: start });
            }
            Simple::new(argument as u8)
                .map(Value::Simple)
                .map_err(|_| DecodeError::IllFormed { offset: start })
        }
        _ => {
            let width = match additional {
                25 => FloatWidth::Half,
                26 => FloatWidth::Single,
                _ => FloatWidth::Double,
            };
            let number = bits_to_f64(width, argument);
            if transport && !number.is_finite() {
                return Err(DecodeError::TransportValue { offset: start });
            }
            let canonical = Float::from_f64(number).map_err(|_| DecodeError::NonShortestFloat { offset: start })?;
            if !transport && (canonical.width() != width || canonical.bits() != argument) {
                return Err(DecodeError::NonShortestFloat { offset: start });
            }
            Ok(Value::Float(canonical))
        }
    }
}

/// A head, read and checked. The envelope's prefix path reads heads
/// without decoding the items under them, which is what keeps it inside
/// its bound over a map of any size.
pub(crate) struct Head {
    pub(crate) major: u8,
    pub(crate) additional: u8,
    pub(crate) argument: u64,
}

/// How many bytes the head beginning with this initial byte occupies. The
/// forms no well-formed encoding produces are one byte, since reading that
/// byte is what refuses them.
pub(crate) const fn head_span(initial: u8) -> usize {
    match initial & 0x1f {
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => 1,
    }
}

/// One head, read and checked against preferred serialization.
///
/// Additional information 31 is the indefinite-length marker for major types
/// 2 through 5 and the break stop code under major type 7; major types 0, 1,
/// and 6 have no indefinite form, and no definite-length item admits the
/// break, so both of those are ill-formed rather than indefinite.
///
/// Preferred serialization governs the arguments of major types 0 through 6
/// only: major type 7's additional information is not an argument magnitude,
/// and §3.3 rules it instead.
pub(crate) fn read_head(input: &[u8], position: &mut usize) -> Result<Head, DecodeError> {
    read_head_policy(input, position, &mut ReadPolicy::Strict)
}

fn read_head_policy(input: &[u8], position: &mut usize, policy: &mut ReadPolicy<'_>) -> Result<Head, DecodeError> {
    let start = *position;
    let &initial = input.get(start).ok_or(DecodeError::Truncated { offset: input.len() })?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    policy.work(head_span(initial), start)?;
    *position = start + 1;

    let argument = match additional {
        0..=23 => u64::from(additional),
        24 => u64::from(read_payload(input, position, 1)?[0]),
        25 => read_argument::<2>(input, position)?,
        26 => read_argument::<4>(input, position)?,
        27 => read_argument::<8>(input, position)?,
        28..=30 => return Err(DecodeError::IllFormed { offset: start }),
        _ if policy.transport() && (2..=5).contains(&major) => 0,
        _ => {
            return Err(if (2..=5).contains(&major) {
                DecodeError::IndefiniteLength { offset: start }
            } else {
                DecodeError::IllFormed { offset: start }
            });
        }
    };

    if !policy.transport() && major != 7 && additional >= 24 && initial_byte(0, argument) & 0x1f != additional {
        return Err(DecodeError::NonPreferredHead { offset: start });
    }

    Ok(Head {
        major,
        additional,
        argument,
    })
}

fn read_argument<const N: usize>(input: &[u8], position: &mut usize) -> Result<u64, DecodeError> {
    let bytes = read_payload(input, position, N as u64)?;
    let mut buffer = [0u8; 8];
    buffer[8 - N..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buffer))
}

// Justified: the length is first bounded by the remaining slice length, which fits usize.
#[allow(clippy::cast_possible_truncation)]
fn read_payload<'a>(input: &'a [u8], position: &mut usize, len: u64) -> Result<&'a [u8], DecodeError> {
    if len > remaining_bytes(input, *position) {
        return Err(DecodeError::Truncated { offset: input.len() });
    }
    let start = *position;
    let end = start + len as usize;
    *position = end;
    Ok(&input[start..end])
}

fn remaining_bytes(input: &[u8], position: usize) -> u64 {
    (input.len() - position) as u64
}

#[cfg(test)]
mod budget_tests;
