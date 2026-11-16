//! Borrowed semantic access to the interchange validator's completed item spans.
//! No CBOR head, integer or container grammar is decoded here.
//! (´[ROOT-amend:storage:canonical-values]´)
use super::{Error, Meter, StorageError};
use pn_interchange::{CanonicalUsage, DecodeError, Value};
use std::cell::{Cell, RefCell};

#[derive(Clone, Copy)]
struct Span {
    offset: usize,
    length: usize,
    payload: usize,
    depth: usize,
    major: u8,
    argument: u64,
}

pub(super) struct Validated<'a> {
    bytes: &'a [u8],
    spans: Vec<Span>,
}

impl<'a> Validated<'a> {
    pub(super) fn new(bytes: &'a [u8], meter: &mut Meter) -> Result<Self, Error> {
        let allowance = meter.limit.bytes.saturating_sub(meter.used.allocation_bytes);
        let meter = RefCell::new(meter);
        let failure = Cell::new(false);
        let mut spans = Vec::new();
        let result = Value::validate_canonical_bytes(
            bytes,
            allowance,
            &mut CanonicalUsage::default(),
            |amount| {
                meter.borrow_mut().allocation(amount).map_err(|_| {
                    failure.set(true);
                })
            },
            |item| {
                #[cfg(test)]
                super::tests::validated_event();
                if failure.get() {
                    return;
                }
                let growth = spans.capacity().max(1);
                if spans.len() == spans.capacity() && meter.borrow_mut().reserve(&mut spans, growth).is_err() {
                    failure.set(true);
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
        if failure.get() {
            return Err(StorageError::ReadLimit.into());
        }
        result.map_err(|error| match error {
            DecodeError::CanonicalLimit { .. }
            | DecodeError::CanonicalAllocation { .. }
            | DecodeError::CanonicalReservation { .. } => StorageError::ReadLimit,
            _ => StorageError::CorruptHistory,
        })?;
        spans.sort_unstable_by_key(|span| span.offset);
        Ok(Self { bytes, spans })
    }

    pub(super) fn root(&self) -> Result<Item<'_>, Error> {
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

#[derive(Clone, Copy)]
pub(super) struct Item<'a> {
    document: &'a Validated<'a>,
    span: Span,
    index: usize,
}
impl<'a> Item<'a> {
    pub(super) fn bytes(self) -> &'a [u8] {
        &self.document.bytes[self.span.offset..self.span.offset + self.span.length]
    }
    pub(super) fn unsigned(self) -> Result<u64, Error> {
        if self.span.major != 0 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(self.span.argument)
    }
    pub(super) fn text(self) -> Result<&'a str, Error> {
        if self.span.major != 3 {
            return Err(StorageError::CorruptHistory.into());
        }
        std::str::from_utf8(&self.bytes()[self.span.payload..]).map_err(|_| StorageError::CorruptHistory.into())
    }
    pub(super) fn blob(self) -> Result<&'a [u8], Error> {
        if self.span.major != 2 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(&self.bytes()[self.span.payload..])
    }
    pub(super) fn null(self) -> bool {
        self.span.major == 7 && self.span.argument == 22
    }
    pub(super) fn children(self) -> Result<Children<'a>, Error> {
        if !matches!(self.span.major, 4 | 5) {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(Children {
            parent: self,
            next: self.index + 1,
        })
    }
    pub(super) fn field(self, field: usize) -> Result<Self, Error> {
        self.children()?.nth(field).ok_or(StorageError::CorruptHistory.into())
    }
    pub(super) fn array(self, length: usize) -> Result<Self, Error> {
        if self.span.major != 4 || self.span.argument != length as u64 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(self)
    }
    pub(super) fn map_value(self, key: u64) -> Result<Self, Error> {
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
pub(super) struct Children<'a> {
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
