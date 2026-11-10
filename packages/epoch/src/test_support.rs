//! Untrusted fixture disclosures made with the ordinary numerical producer.
//! (´def:admission:test-support´)
mod base;
mod fixture;
pub use fixture::Check;

/// Build two historical boundaries, including ridge prices and an empty successor.
/// The return value has no admission authority; callers must run public restoration.
/// (´def:admission:test-support´)
/// # Panics
/// Panics only if the fixed development fixture ceases to satisfy its producer contracts.
#[must_use]
pub fn ridge_disclosures() -> (crate::publication::disclosures::Disclosure, Check) {
    fixture::complete()
}

#[cfg(test)]
mod tests {
    /// Claim: The development builder supplies untrusted two-boundary ridge disclosures whose prices, retained final gates and schedule survive independent public restoration; a changed ridge query is refused.
    /// ´claim:admission:test-support-restores-ridge-disclosures´
    /// ´test:unit:ridge-fixture-restores´
    #[test]
    fn ridge_fixture_restores() {
        let (raw, check) = super::ridge_disclosures();
        assert_eq!(raw.frames.len(), 2);
        assert_eq!(raw.frames[1].sequence, []);
        for frame in &raw.frames {
            assert!(frame.price.ridge.is_some());
            assert!(frame.closure.bindings.iter().all(|b| b.price.ridge.is_some()));
            assert!(!frame.compiled.ledger.debits.is_empty());
            assert!(frame.compiled.ledger.debits.values().all(|d| d.price.ridge.is_some()));
            assert_eq!(frame.closure.final_gates.standing.is_some(), !frame.sequence.is_empty());
            assert_ne!(frame.next.publications, []);
        }
        let restored = crate::publication::disclosures::restore(raw.clone(), &check).unwrap();
        assert_eq!(restored.disclosures(), raw);
        let mut changed = raw;
        changed.frames[0].price.ridge.as_mut().unwrap().record.queries[0].precision += 1;
        assert!(crate::publication::disclosures::restore(changed, &check).is_err());
    }
}
