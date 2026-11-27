//! Passive successor frame amounts, names and ordered entries.
//! (´[ROOT-amend:identity:frame-document-design]´)

/// An unsigned gross amount in the selected network's minimal burnt-asset unit.
/// Every fixed-width byte pattern is an amount; this is not a historical burn amount.
/// (´[ROOT-def:identity:frame-amount]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrossAmount([u8; 32]);

impl GrossAmount {
    /// Interpret all 32 big-endian bytes without a representational refusal.
    /// (´[ROOT-def:identity:frame-amount]´)
    #[tracing::instrument(
        name = "amend:identity:frame-document-design",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:frame-document-design",
            operation = "gross-amount-from-be-bytes",
            source_item = "frame::GrossAmount::from_be_bytes"
        ),
        ret
    )]
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the original big-endian bytes.
    /// Justified: Immutable carrier access inherits the operation that produced the value.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An untrusted expected reference to a complete frame document.
/// Construction establishes no binding to any document.
/// (´[ROOT-amend:identity:frame-document-design]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameName([u8; 32]);

impl FrameName {
    /// Retain the supplied reference bytes without a binding claim.
    /// (´[ROOT-amend:identity:frame-document-design]´)
    #[tracing::instrument(
        name = "amend:identity:frame-document-design",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:frame-document-design",
            operation = "frame-name-from-bytes",
            source_item = "frame::FrameName::from_bytes"
        ),
        ret
    )]
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the untrusted reference bytes.
    /// Justified: Immutable carrier access inherits the operation that produced the value.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Explicit per-construction entry and storage ceilings.
/// (´[ROOT-amend:identity:frame-document-design]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameAllowances {
    /// Maximum number of entries retained in this frame.
    pub entries: usize,
    /// Maximum bytes of typed entry storage reserved for this frame.
    pub allocation_bytes: usize,
}

/// Diagnostic reason for an unavailable frame construction budget.
/// (´[ROOT-amend:identity:frame-document-design]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameBudgetReason {
    /// The entry count exceeds the declared ceiling.
    Entries,
    /// Typed-storage size arithmetic cannot be represented.
    Representation,
    /// Typed-entry storage exceeds the declared byte ceiling.
    CollectionAllocation,
    /// Allocating typed-entry storage failed.
    Allocation,
}

/// First cause of a refused ordered frame construction.
/// (´[ROOT-amend:identity:frame-document-design]´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// At least one adjacent Actor name descends.
    #[error("frame entries are out of order")]
    Order,
    /// At least one adjacent Actor name is repeated.
    #[error("frame contains a duplicate Actor name")]
    Duplicate,
    /// Entry, storage-arithmetic, storage-ceiling or allocation refusal.
    #[error("frame construction exceeds available budget: {0:?}")]
    UnavailableBudget(FrameBudgetReason),
}

fn checked_allocation_bytes(entries: usize) -> Result<usize, FrameError> {
    entries
        .checked_mul(std::mem::size_of::<([u8; 32], GrossAmount)>())
        .ok_or(FrameError::UnavailableBudget(FrameBudgetReason::Representation))
}

fn reserve_entries(entries: usize) -> Result<Vec<([u8; 32], GrossAmount)>, FrameError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(entries)
        .map_err(|_| FrameError::UnavailableBudget(FrameBudgetReason::Allocation))?;
    Ok(owned)
}

/// Ordered association of opaque Actor names and unsigned gross amounts.
/// It does not certify the required Actor domain or any recognized destruction.
/// (´[ROOT-rule:identity:frame-document-domain]´)
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    entries: Vec<([u8; 32], GrossAmount)>,
}

impl Frame {
    /// Copy an already ordered finite slice under explicit entry and storage allowances.
    /// (´[ROOT-amend:identity:frame-document-design]´)
    ///
    /// # Errors
    /// Returns unavailable budget before checking names, then Order before Duplicate,
    /// then unavailable budget if the checked slice cannot be allocated.
    #[tracing::instrument(
        name = "amend:identity:frame-document-design",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "amend:identity:frame-document-design",
            operation = "frame-from-entries",
            source_item = "frame::Frame::from_entries"
        ),
        ret
    )]
    pub fn from_entries(entries: &[([u8; 32], GrossAmount)], allowances: FrameAllowances) -> Result<Self, FrameError> {
        let result = (|| {
            if entries.len() > allowances.entries {
                return Err(FrameError::UnavailableBudget(FrameBudgetReason::Entries));
            }
            let bytes = checked_allocation_bytes(entries.len())?;
            if bytes > allowances.allocation_bytes {
                return Err(FrameError::UnavailableBudget(FrameBudgetReason::CollectionAllocation));
            }
            if entries.windows(2).any(|pair| pair[0].0 > pair[1].0) {
                return Err(FrameError::Order);
            }
            if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(FrameError::Duplicate);
            }
            let mut owned = reserve_entries(entries.len())?;
            owned.extend_from_slice(entries);
            Ok(Self { entries: owned })
        })();
        if result.is_err() {
            crate::refused();
        }
        result
    }

    /// Borrow the checked, immutable association in its supplied order.
    /// Justified: Immutable carrier access inherits the constructor or reader operation.
    #[must_use]
    pub fn entries(&self) -> &[([u8; 32], GrossAmount)] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Frame, FrameAllowances, FrameBudgetReason, FrameError, FrameName, GrossAmount, checked_allocation_bytes, reserve_entries,
    };

    /// Claim: The two fixed-width carriers retain every supplied byte and expose immutable borrowed views without adding a validity or identity claim.
    /// ´claim:identity:frame-fixed-width-views´
    /// ´test:unit:frame-fixed-width-views´
    #[test]
    fn frame_fixed_width_views() {
        for bytes in [[0; 32], [255; 32], std::array::from_fn(|index| u8::try_from(index).unwrap())] {
            assert_eq!(GrossAmount::from_be_bytes(bytes).bytes(), &bytes);
            assert_eq!(FrameName::from_bytes(bytes).bytes(), &bytes);
        }
    }

    /// Claim: Frame construction reports each unavailable-budget reason, checks entry and allocation ceilings before names, checks every descent before any duplicate including a later descent, and retains the accepted slice unchanged.
    /// ´claim:identity:frame-records-constructor-order´
    /// ´test:unit:frame-records-constructor-order´
    #[test]
    fn frame_records_constructor_order() {
        let amount = GrossAmount::from_be_bytes([0; 32]);
        let high = ([2; 32], amount);
        let low = ([1; 32], amount);
        let mixed = [high, low, low];
        let zero = ([0; 32], amount);
        let enough = FrameAllowances {
            entries: 3,
            allocation_bytes: 3 * 64,
        };
        assert_eq!(
            Frame::from_entries(&mixed, FrameAllowances { entries: 2, ..enough }),
            Err(FrameError::UnavailableBudget(FrameBudgetReason::Entries))
        );
        assert_eq!(
            Frame::from_entries(
                &mixed,
                FrameAllowances {
                    allocation_bytes: 2 * 64,
                    ..enough
                }
            ),
            Err(FrameError::UnavailableBudget(FrameBudgetReason::CollectionAllocation))
        );
        assert_eq!(Frame::from_entries(&mixed, enough), Err(FrameError::Order));
        assert_eq!(Frame::from_entries(&[low, low, zero], enough), Err(FrameError::Order));
        assert_eq!(Frame::from_entries(&[low, low], enough), Err(FrameError::Duplicate));
        assert_eq!(
            checked_allocation_bytes(usize::MAX),
            Err(FrameError::UnavailableBudget(FrameBudgetReason::Representation))
        );
        assert_eq!(
            reserve_entries(usize::MAX),
            Err(FrameError::UnavailableBudget(FrameBudgetReason::Allocation))
        );
        let ordered = [low, high];
        let frame = Frame::from_entries(&ordered, enough).unwrap();
        assert_eq!(frame.entries(), &ordered);
        let empty = Frame::from_entries(
            &[],
            FrameAllowances {
                entries: 0,
                allocation_bytes: 0,
            },
        )
        .unwrap();
        assert_eq!(empty.entries().len(), 0);
        let one = Frame::from_entries(
            &[([0; 32], GrossAmount::from_be_bytes([255; 32]))],
            FrameAllowances {
                entries: 1,
                allocation_bytes: 64,
            },
        )
        .unwrap();
        assert_eq!(one.entries()[0].1.bytes(), &[255; 32]);
    }
}
