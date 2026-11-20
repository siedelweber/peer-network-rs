//! Borrowed semantic access to the interchange validator's completed item spans.
//! No CBOR head, integer or container grammar is decoded here.
//! (´[ROOT-amend:storage:canonical-values]´)
use super::{DISCLOSURE_RECIPE, Error, Family, Meter, PAYLOAD_RECIPE, StorageError, digest};
use crate::storage::tree::audit::{AuditFailure, AuditMeter, AuditSite};
use pn_interchange::{CanonicalUsage, DecodeError, Value};
use std::cell::RefCell;

#[derive(Clone, Copy)]
struct Span {
    offset: usize,
    length: usize,
    payload: usize,
    depth: usize,
    major: u8,
    argument: u64,
}

pub(crate) struct Validated<'a> {
    bytes: &'a [u8],
    spans: Vec<Span>,
}

impl<'a> Validated<'a> {
    #[cfg(test)]
    pub(crate) fn for_position_test(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut meter = Meter {
            limit: super::ReadBudget {
                rows: usize::MAX,
                bytes: usize::MAX,
            },
            used: super::Usage::default(),
        };
        Self::new(bytes, &mut meter)
    }

    pub(super) fn new(bytes: &'a [u8], meter: &mut Meter) -> Result<Self, Error> {
        let allowance = meter.limit.bytes.saturating_sub(meter.used.allocation_bytes);
        let meter = RefCell::new(meter);
        Self::with_reservations(
            bytes,
            allowance,
            |amount| meter.borrow_mut().allocation(amount),
            |spans, growth| meter.borrow_mut().reserve(spans, growth),
            |error| match error {
                DecodeError::CanonicalLimit { .. }
                | DecodeError::CanonicalAllocation { .. }
                | DecodeError::CanonicalReservation { .. } => StorageError::ReadLimit.into(),
                _ => StorageError::CorruptHistory.into(),
            },
        )
    }

    pub(in crate::storage::tree) fn audit(
        bytes: &'a [u8],
        meter: &mut AuditMeter,
        site: AuditSite<'_>,
    ) -> Result<Self, AuditFailure> {
        let allowance = meter.remaining_allocation();
        let meter = RefCell::new(meter);
        Self::with_reservations(
            bytes,
            allowance,
            |amount| meter.borrow_mut().allocation(amount, site).map(|_| ()),
            |spans, growth| meter.borrow_mut().reserve(spans, growth, site),
            |error| match error {
                DecodeError::CanonicalAllocation { .. } => meter.borrow_mut().allocated(site),
                DecodeError::CanonicalLimit { .. } | DecodeError::CanonicalReservation { .. } => {
                    meter.borrow_mut().refused(StorageError::ReadLimit, site)
                }
                _ => meter.borrow_mut().refused(StorageError::CorruptHistory, site),
            },
        )
    }

    fn with_reservations<E>(
        bytes: &'a [u8],
        allowance: usize,
        mut allocation: impl FnMut(usize) -> Result<(), E>,
        mut reserve_spans: impl FnMut(&mut Vec<Span>, usize) -> Result<(), E>,
        decode: impl FnOnce(DecodeError) -> E,
    ) -> Result<Self, E> {
        let failure = RefCell::new(None);
        let mut spans = Vec::new();
        let result = Value::validate_canonical_bytes(
            bytes,
            allowance,
            &mut CanonicalUsage::default(),
            |amount| {
                allocation(amount).map_err(|error| {
                    *failure.borrow_mut() = Some(error);
                })
            },
            |item| {
                #[cfg(test)]
                super::tests::validated_event();
                if failure.borrow().is_some() {
                    return;
                }
                let growth = spans.capacity().max(1);
                if spans.len() == spans.capacity()
                    && let Err(error) = reserve_spans(&mut spans, growth)
                {
                    *failure.borrow_mut() = Some(error);
                    return;
                }
                spans.push(Span {
                    offset: item.offset,
                    length: item.bytes.len(),
                    payload: item.payload_offset,
                    depth: item.depth,
                    major: item.major,
                    argument: item.argument,
                });
            },
        );
        if let Some(error) = failure.into_inner() {
            return Err(error);
        }
        result.map_err(decode)?;
        spans.sort_unstable_by_key(|span| span.offset);
        Ok(Self { bytes, spans })
    }

    pub(crate) fn root(&self) -> Result<Item<'_>, Error> {
        self.item(0)
    }
    fn item(&self, index: usize) -> Result<Item<'_>, Error> {
        let span = *self.spans.get(index).ok_or(StorageError::CorruptHistory)?;
        Ok(Item {
            document: self,
            span,
            index,
        })
    }
}

/// Validate the same stored history envelope for both bounded readers.
pub(in crate::storage::tree) fn history_payload(
    validated: &Validated<'_>,
    family: Family,
    content: &[u8],
    stored_digest: [u8; 32],
    disclosure: Option<[u8; 32]>,
) -> Result<(), Error> {
    let envelope = validated.root()?.array(3)?;
    if envelope.field(0)?.text()? != PAYLOAD_RECIPE
        || envelope.field(1)?.text()? != family.name()
        || digest(PAYLOAD_RECIPE, content) != stored_digest
    {
        return Err(StorageError::CorruptHistory.into());
    }
    if family == Family::UnsettledRecognition {
        let body = envelope.field(2)?.array(4)?;
        let input = body.field(2)?;
        let expected = digest(DISCLOSURE_RECIPE, input.bytes());
        if body.field(0)?.text()? != DISCLOSURE_RECIPE || body.field(1)?.blob()? != expected || disclosure != Some(expected) {
            return Err(StorageError::CorruptHistory.into());
        }
    } else if disclosure.is_some() {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct Item<'a> {
    document: &'a Validated<'a>,
    span: Span,
    index: usize,
}
impl<'a> Item<'a> {
    pub(crate) fn bytes(self) -> &'a [u8] {
        &self.document.bytes[self.span.offset..self.span.offset + self.span.length]
    }
    pub(crate) fn unsigned(self) -> Result<u64, Error> {
        if self.span.major != 0 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(self.span.argument)
    }
    pub(crate) fn text(self) -> Result<&'a str, Error> {
        if self.span.major != 3 {
            return Err(StorageError::CorruptHistory.into());
        }
        std::str::from_utf8(&self.bytes()[self.span.payload..]).map_err(|_| StorageError::CorruptHistory.into())
    }
    pub(crate) fn blob(self) -> Result<&'a [u8], Error> {
        if self.span.major != 2 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(&self.bytes()[self.span.payload..])
    }
    pub(crate) fn null(self) -> bool {
        self.span.major == 7 && self.span.argument == 22
    }
    pub(crate) fn children(self) -> Result<Children<'a>, Error> {
        if !matches!(self.span.major, 4 | 5) {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(Children {
            parent: self,
            next: self.index + 1,
        })
    }
    pub(crate) fn field(self, field: usize) -> Result<Self, Error> {
        self.children()?.nth(field).ok_or(StorageError::CorruptHistory.into())
    }
    pub(crate) fn array(self, length: usize) -> Result<Self, Error> {
        if self.span.major != 4 || self.span.argument != length as u64 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(self)
    }
    pub(crate) fn map_value(self, key: u64) -> Result<Self, Error> {
        if self.span.major != 5 {
            return Err(StorageError::CorruptHistory.into());
        }
        let mut children = self.children()?;
        while let Some(candidate) = children.next() {
            let value = children.next().ok_or(StorageError::CorruptHistory)?;
            if candidate.unsigned()? == key {
                return Ok(value);
            }
        }
        Err(StorageError::CorruptHistory.into())
    }
}
pub(crate) struct Children<'a> {
    parent: Item<'a>,
    next: usize,
}
impl<'a> Iterator for Children<'a> {
    type Item = Item<'a>;
    /// Justified: Traversing completed public spans inherits the enclosing metered validator operation.
    fn next(&mut self) -> Option<Self::Item> {
        let end = self.parent.span.offset + self.parent.span.length;
        while let Some(span) = self.parent.document.spans.get(self.next) {
            let index = self.next;
            self.next += 1;
            if span.offset >= end {
                return None;
            }
            if span.depth == self.parent.span.depth + 1 {
                return self.parent.document.item(index).ok();
            }
        }
        None
    }
}
