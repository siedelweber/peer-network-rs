//! Pinning of explicit chain evidence on the observed signed chain under (´[ROOT-rule:devnet:settlement]´).
//! Marker recognition, accepted sets and epoch snapshots are outside this carrier.
use std::collections::BTreeMap;

/// Successor blocks after which an event's chain evidence pins.
/// (´def:wallet:pinning-successors´)
pub const PINNING_SUCCESSORS: u64 = 6;

/// One explicit evidence output located by public identifiers on one observed chain.
/// (´def:wallet:settlement-evidence´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evidence {
    /// Display-order transaction identifier.
    pub transaction: [u8; 32],
    /// Output index of the evidence output.
    pub output: u32,
    /// Display-order hash of the block claimed to include the transaction.
    pub block: [u8; 32],
    /// Height claimed for that block.
    pub height: u64,
    /// Explicit amount selected by the evidence decoder.
    pub amount: u64,
}

/// Public chain positions read for one observation, and the evidence located on them.
/// (´def:wallet:settlement-observation´)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    /// Height of the observed best block.
    pub tip: u64,
    /// Active-chain block hashes read at the listed heights.
    pub hashes: BTreeMap<u64, [u8; 32]>,
    /// Located evidence, possibly reported more than once.
    pub evidence: Vec<Evidence>,
}

/// Evidence that has not yet reached the pinning depth.
/// (´def:wallet:pending-evidence´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// The located evidence.
    pub evidence: Evidence,
    /// Successor blocks observed above its block.
    pub successors: u64,
}

/// Result of an admitted observation.
/// (´def:wallet:settlement-view´)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct View {
    /// Every pinned evidence output, once per outpoint, in outpoint order.
    pub pinned: Vec<Evidence>,
    /// Evidence below the pinning depth, once per outpoint; recomputed on every observation.
    pub pending: Vec<Pending>,
    /// Sum of pinned amounts.
    pub pinned_total: u64,
    /// Highest pinned height and its block hash, which every later chain must retain.
    pub floor: Option<(u64, [u8; 32])>,
}

/// Public settlement refusal; a fault is retained for the run.
/// (´def:wallet:settlement-refusal´)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementRefusal {
    /// A chain position the decision needs was not read; nothing is guessed.
    Unavailable {
        /// Height whose active-chain hash is absent.
        height: u64,
    },
    /// Evidence is not on the observed chain at its claimed height.
    Stale {
        /// Display-order transaction identifier.
        transaction: [u8; 32],
        /// Output index.
        output: u32,
    },
    /// One outpoint was reported with different locators or amounts.
    Alias {
        /// Display-order transaction identifier.
        transaction: [u8; 32],
        /// Output index.
        output: u32,
    },
    /// The pinned total does not fit the amount type.
    Overflow,
    /// The observed chain no longer holds the pinned floor: a realization fault for the run.
    /// Pinned amounts are retained unchanged and every later observation returns this fault.
    Fault {
        /// Pinned floor height the observed chain conflicts with.
        height: u64,
        /// Retained pinned total, never edited downward.
        retained: u64,
    },
}

/// Pinned evidence and any fault for one run; pending evidence is never stored.
/// (´def:wallet:settlement´)
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Settlement {
    pinned: BTreeMap<([u8; 32], u32), Evidence>,
    fault: Option<SettlementRefusal>,
}

/// The floor is the highest pinned event's height and block; there is none before any evidence pins.
/// Its block commits to every lower block, so holding it holds every pinned event.
fn floor(pinned: &BTreeMap<([u8; 32], u32), Evidence>) -> Option<(u64, [u8; 32])> {
    pinned
        .values()
        .max_by_key(|evidence| evidence.height)
        .map(|evidence| (evidence.height, evidence.block))
}

impl Settlement {
    /// Admit one observation of the active chain: check the pinned floor, then pin evidence with at least
    /// the declared pinning successors and report the rest as pending.
    /// (´sig:wallet:settlement-observe´)
    ///
    /// # Errors
    /// Refuses unread positions, off-chain or aliased evidence and an overflowing total without changing state;
    /// a floor conflict records and returns the run fault.
    #[tracing::instrument(
        name = "sig:design:devnet",
        fields(
            execution_owner = "WALLET",
            claim_owner = "ROOT",
            claim_label = "sig:design:devnet",
            operation = "settlement-observe",
            source_item = "settlement::Settlement::observe"
        ),
        ret
    )]
    pub fn observe(&mut self, observation: &Observation) -> Result<View, SettlementRefusal> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        let hash = |height: u64| {
            observation
                .hashes
                .get(&height)
                .copied()
                .ok_or(SettlementRefusal::Unavailable { height })
        };
        if let Some((height, block)) = floor(&self.pinned)
            && (observation.tip < height || hash(height)? != block)
        {
            // Every committed pinned set had a checked total, so saturation never binds.
            let retained = self
                .pinned
                .values()
                .fold(0u64, |total, evidence| total.saturating_add(evidence.amount));
            let fault = SettlementRefusal::Fault { height, retained };
            self.fault = Some(fault);
            return Err(fault);
        }
        let mut located = BTreeMap::new();
        for evidence in &observation.evidence {
            let key = (evidence.transaction, evidence.output);
            let alias = SettlementRefusal::Alias {
                transaction: evidence.transaction,
                output: evidence.output,
            };
            if evidence.height > observation.tip || hash(evidence.height)? != evidence.block {
                return Err(SettlementRefusal::Stale {
                    transaction: evidence.transaction,
                    output: evidence.output,
                });
            }
            if located.insert(key, *evidence).is_some_and(|earlier| earlier != *evidence)
                || self.pinned.get(&key).is_some_and(|pinned| pinned != evidence)
            {
                return Err(alias);
            }
        }
        let mut pinned = self.pinned.clone();
        let mut pending = Vec::new();
        for (key, evidence) in located {
            let successors = observation.tip - evidence.height;
            if successors >= PINNING_SUCCESSORS {
                pinned.entry(key).or_insert(evidence);
            } else {
                pending.push(Pending { evidence, successors });
            }
        }
        let pinned_total = pinned
            .values()
            .try_fold(0u64, |total, evidence| total.checked_add(evidence.amount))
            .ok_or(SettlementRefusal::Overflow)?;
        self.pinned = pinned;
        Ok(View {
            pinned: self.pinned.values().copied().collect(),
            pending,
            pinned_total,
            floor: floor(&self.pinned),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(fork: u64, from: u64, tip: u64) -> BTreeMap<u64, [u8; 32]> {
        (0..=tip)
            .map(|height| {
                let mut hash = [0; 32];
                hash[..8].copy_from_slice(&height.to_be_bytes());
                if height >= from {
                    hash[31] = u8::try_from(fork).unwrap();
                }
                (height, hash)
            })
            .collect()
    }

    fn evidence(transaction: u8, height: u64, hashes: &BTreeMap<u64, [u8; 32]>, amount: u64) -> Evidence {
        Evidence {
            transaction: [transaction; 32],
            output: 0,
            block: hashes[&height],
            height,
            amount,
        }
    }

    fn observation(tip: u64, hashes: &BTreeMap<u64, [u8; 32]>, evidence: Vec<Evidence>) -> Observation {
        Observation {
            tip,
            hashes: hashes.clone(),
            evidence,
        }
    }

    /// Claim: Evidence with fewer than six successor blocks stays pending with its successor count, adds nothing to the pinned total and sets no floor; at exactly six successors it pins with its amount and its height and block become the floor; later empty blocks and an unread hash at a height unrelated to pinned evidence keep the pinned total and floor, while an unread floor height is refused rather than guessed.
    /// ´claim:wallet:settlement-pins-at-declared-depth´
    /// ´test:unit:pinning-depth´
    #[test]
    fn pinning_depth() {
        let hashes = chain(0, 0, 40);
        let first = evidence(1, 10, &hashes, 7);
        let mut settlement = Settlement::default();
        let view = settlement.observe(&observation(15, &hashes, vec![first])).unwrap();
        assert_eq!(
            view.pending,
            vec![Pending {
                evidence: first,
                successors: 5
            }]
        );
        assert_eq!((view.pinned.len(), view.pinned_total, view.floor), (0, 0, None));
        let view = settlement.observe(&observation(16, &hashes, vec![first])).unwrap();
        assert_eq!((view.pinned, view.pending, view.pinned_total), (vec![first], vec![], 7));
        assert_eq!(view.floor, Some((10, hashes[&10])));
        for tip in [17, 25, 40] {
            let view = settlement.observe(&observation(tip, &hashes, vec![])).unwrap();
            assert_eq!((view.pinned_total, view.floor), (7, Some((10, hashes[&10]))));
        }
        let mut partial = observation(40, &hashes, vec![]);
        partial.hashes.retain(|height, _| *height == 10);
        let view = settlement.observe(&partial).unwrap();
        assert_eq!((view.pinned_total, view.floor), (7, Some((10, hashes[&10]))));
        partial.hashes.remove(&10);
        let before = settlement.clone();
        assert_eq!(
            settlement.observe(&partial),
            Err(SettlementRefusal::Unavailable { height: 10 })
        );
        assert_eq!(settlement, before);
        let mut fresh = Settlement::default();
        assert!(
            fresh
                .observe(&observation(3, &hashes, vec![evidence(2, 3, &hashes, 1)]))
                .unwrap()
                .floor
                .is_none()
        );
    }

    /// Claim: A replacement above the highest pinned event changes only pending evidence, even at or below the pinning cutoff, and evidence left on the replaced branch is refused as stale; a replacement of the floor block, or a chain shorter than its height, is a realization fault that retains the pinned total and is returned for every later observation.
    /// ´claim:wallet:settlement-replacement-keeps-pinned-floor´
    /// ´test:unit:replacement-floor´
    #[test]
    fn replacement_floor() {
        let original = chain(0, 0, 30);
        let pinned = evidence(1, 10, &original, 5);
        let shallow = evidence(2, 19, &original, 3);
        let mut settlement = Settlement::default();
        let view = settlement
            .observe(&observation(20, &original, vec![pinned, shallow]))
            .unwrap();
        assert_eq!((view.pinned_total, view.pending.len()), (5, 1));
        let replaced = chain(1, 18, 21);
        assert_eq!(
            settlement.observe(&observation(21, &replaced, vec![pinned, shallow])),
            Err(SettlementRefusal::Stale {
                transaction: [2; 32],
                output: 0
            })
        );
        let moved = evidence(2, 21, &replaced, 3);
        let view = settlement.observe(&observation(21, &replaced, vec![pinned, moved])).unwrap();
        assert_eq!((view.pinned, view.pinned_total), (vec![pinned], 5));
        assert_eq!(
            view.pending,
            vec![Pending {
                evidence: moved,
                successors: 0
            }]
        );
        // Heights 11 to 40 are replaced; 11 is below the cutoff 40 - 6, yet the pinned block 10 stays.
        let above = chain(2, 11, 40);
        let view = settlement.observe(&observation(40, &above, vec![pinned])).unwrap();
        assert_eq!(
            (view.pinned, view.pinned_total, view.floor),
            (vec![pinned], 5, Some((10, original[&10])))
        );
        let deep = chain(3, 10, 40);
        let fault = SettlementRefusal::Fault { height: 10, retained: 5 };
        assert_eq!(settlement.observe(&observation(40, &deep, vec![])), Err(fault));
        assert_eq!(settlement.observe(&observation(40, &above, vec![pinned])), Err(fault));
        let mut shorter = Settlement::default();
        shorter.observe(&observation(20, &original, vec![pinned])).unwrap();
        assert_eq!(
            shorter.observe(&observation(9, &original, vec![])),
            Err(SettlementRefusal::Fault { height: 10, retained: 5 })
        );
    }

    /// Claim: The same outpoint reported repeatedly counts once in pending and pinned evidence, distinct outpoints add exactly, an outpoint reported with a different block, height or amount is refused as an alias without changing state, and an overflowing pinned total is refused.
    /// ´claim:wallet:settlement-counts-each-outpoint-once´
    /// ´test:unit:outpoint-once´
    #[test]
    fn outpoint_once() {
        let hashes = chain(0, 0, 30);
        let first = evidence(1, 10, &hashes, 5);
        let mut second = evidence(1, 10, &hashes, 4);
        second.output = 1;
        let mut settlement = Settlement::default();
        let view = settlement
            .observe(&observation(12, &hashes, vec![first, first, second, first]))
            .unwrap();
        assert_eq!(view.pending.len(), 2);
        let view = settlement
            .observe(&observation(16, &hashes, vec![first, second, second]))
            .unwrap();
        assert_eq!((view.pinned, view.pinned_total), (vec![first, second], 9));
        let view = settlement.observe(&observation(20, &hashes, vec![first])).unwrap();
        assert_eq!(view.pinned_total, 9);
        let before = settlement.clone();
        for alias in [
            Evidence { amount: 6, ..first },
            Evidence {
                block: hashes[&11],
                height: 11,
                ..first
            },
        ] {
            assert_eq!(
                settlement.observe(&observation(20, &hashes, vec![alias])),
                Err(SettlementRefusal::Alias {
                    transaction: [1; 32],
                    output: 0
                })
            );
            assert_eq!(settlement, before);
        }
        let fresh_a = evidence(3, 12, &hashes, 2);
        assert_eq!(
            Settlement::default().observe(&observation(12, &hashes, vec![fresh_a, Evidence { amount: 3, ..fresh_a }])),
            Err(SettlementRefusal::Alias {
                transaction: [3; 32],
                output: 0
            })
        );
        let large = evidence(4, 1, &hashes, u64::MAX);
        let mut overflow = Settlement::default();
        overflow.observe(&observation(7, &hashes, vec![large])).unwrap();
        assert_eq!(
            overflow.observe(&observation(8, &hashes, vec![large, evidence(5, 2, &hashes, 1)])),
            Err(SettlementRefusal::Overflow)
        );
    }
}
