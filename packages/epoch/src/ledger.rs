//! Final ledger derivation from complete acts and recognized destruction identities.
//! (´def:compiler:final-ledger´)
use std::collections::{BTreeMap, BTreeSet};

use nrz_cas::{
    Rational,
    limits::{Budget, Limits},
};
use pn_graph::registration::{RegistrationError, RegistrationVerifier};
use pn_records::{
    ActId, ValidatedHistory,
    burn::{Address, RecognizedMarkers},
    numerics::{ActionCount, BurnAmount, ChargedPrice, ChargedVintage, NumericContext, NumericError},
};

use crate::CompilerInputs;

/// One marker's cumulative snapshot and first-accepted increments by original address.
/// (´def:compiler:final-ledger´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnSnapshot {
    pub boundary: u64,
    pub gross: BTreeMap<Address, BurnAmount>,
    pub increment: BTreeMap<Address, BurnAmount>,
}

/// Derived values, not independently asserted replacement balances or publication bytes.
/// (´def:compiler:final-ledger´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalLedger {
    pub snapshots: Vec<BurnSnapshot>,
    pub balances: BTreeMap<Address, BurnAmount>,
    pub counts: BTreeMap<Address, ActionCount>,
    pub debits: BTreeMap<ActId, ChargedVintage>,
}

/// No partial ledger escapes a failed derivation.
/// (´def:compiler:final-ledger´)
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("incomplete or unauthorized act: {0}")]
    Formation(#[from] RegistrationError),
    #[error("numeric carrier: {0}")]
    Numeric(#[from] NumericError),
    #[error("exact arithmetic: {0}")]
    Arithmetic(#[from] nrz_cas::Fault),
    #[error("boundary inputs, price vintages and marker sequence do not cover the same prefix")]
    Boundary,
    #[error("burn units differ")]
    Units,
    #[error("price differs from the boundary's declared numeraire or floor")]
    Price,
    #[error("actor has insufficient own balance at the completed boundary")]
    InsufficientBalance { address: Address, boundary: u64 },
    #[error("action count exceeds the carrier")]
    Count,
}

/// Replay final balances and vintage debits from the empty marker and ledger.
/// (´[ROOT-alg:design:ledger]´)
///
/// Inputs and prices cover epochs one through k; markers may extend beyond k.
/// Marker recognition is a premise, not independent external finality evidence.
/// The internal Actor spelling is its permanently bound opaque address.
/// # Errors
/// Refuses inconsistent prefixes, price coordinates, units, unformed acts, arithmetic exhaustion or insolvency.
#[tracing::instrument(
    name = "alg:design:ledger",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "alg:design:ledger",
        source_item = "ledger::compile_ledger"
    ),
    ret
)]
pub fn compile_ledger(
    inputs: &[CompilerInputs],
    prices: &[ChargedPrice],
    markers: &RecognizedMarkers,
    history: &ValidatedHistory,
    verifier: &impl RegistrationVerifier,
    numeric: &mut NumericContext,
    limits: Limits,
) -> Result<FinalLedger, LedgerError> {
    let last = inputs.last().ok_or(LedgerError::Boundary)?.parameters().boundary;
    if inputs.len() != prices.len()
        || u64::try_from(inputs.len()).ok() != Some(last)
        || markers
            .markers()
            .first()
            .is_none_or(|m| m.identity().index != 0 || !m.destructions().is_empty())
        || markers.markers().len() <= inputs.len()
        || history.acts().iter().any(|a| a.position().0 > last)
    {
        return Err(LedgerError::Boundary);
    }
    pn_graph::formation::reconstruct_replay(history, verifier)?;
    let mut budget = Budget::new(limits)?;
    let mut gross = BTreeMap::new();
    let mut balances = BTreeMap::new();
    let mut counts = BTreeMap::new();
    let mut debits = BTreeMap::new();
    let mut snapshots = Vec::new();
    let mut seen = BTreeSet::new();
    let unit = inputs[0].parameters().numeraire.amount().unit();
    for (offset, (input, price)) in inputs.iter().zip(prices).enumerate() {
        let boundary = u64::try_from(offset).map_err(|_| LedgerError::Boundary)? + 1;
        if input.parameters().boundary != boundary || markers.markers()[offset + 1].identity().index != boundary {
            return Err(LedgerError::Boundary);
        }
        if input.parameters().numeraire.amount().unit() != unit {
            return Err(LedgerError::Units);
        }
        let expected = numeric.charged_price(price.wall(), &input.parameters().numeraire, input.constants().content().floor)?;
        if &expected != price {
            return Err(LedgerError::Price);
        }
        let mut increment = BTreeMap::new();
        for (identity, record) in markers.markers()[offset + 1].destructions() {
            if record.amount.unit() != unit {
                return Err(LedgerError::Units);
            }
            counts.entry(record.address.clone()).or_insert(ActionCount(0));
            if seen.insert(identity.clone()) {
                add(&mut gross, &record.address, record.amount.exact(), &mut budget)?;
                add(&mut increment, &record.address, record.amount.exact(), &mut budget)?;
                add(&mut balances, &record.address, record.amount.exact(), &mut budget)?;
            }
        }
        for act in history.acts().iter().filter(|act| act.position().0 == boundary) {
            let address = Address(act.id().author.clone());
            let count = counts.entry(address.clone()).or_insert(ActionCount(0));
            count.0 = count.0.checked_add(1).ok_or(LedgerError::Count)?;
            let debit = numeric.consummate(price, ActionCount(1), boundary)?;
            let charged = Rational::parse(debit.charged().exact(), &mut budget)?;
            let balance = balances.entry(address).or_insert(Rational::parse("0", &mut budget)?);
            *balance = balance.sub(&charged, &mut budget)?;
            debits.insert(act.id().clone(), debit);
        }
        if let Some((address, _)) = balances.iter().find(|(_, balance)| balance.is_negative()) {
            return Err(LedgerError::InsufficientBalance {
                address: address.clone(),
                boundary,
            });
        }
        snapshots.push(BurnSnapshot {
            boundary,
            gross: amounts(&gross, unit, numeric, &mut budget)?,
            increment: amounts(&increment, unit, numeric, &mut budget)?,
        });
    }
    Ok(FinalLedger {
        snapshots,
        balances: amounts(&balances, unit, numeric, &mut budget)?,
        counts,
        debits,
    })
}

fn add(
    values: &mut BTreeMap<Address, Rational>,
    address: &Address,
    spelling: &str,
    budget: &mut Budget,
) -> Result<(), LedgerError> {
    let value = Rational::parse(spelling, budget)?;
    let old = values.entry(address.clone()).or_insert(Rational::parse("0", budget)?);
    *old = old.add(&value, budget)?;
    Ok(())
}

fn amounts(
    values: &BTreeMap<Address, Rational>,
    unit: &str,
    numeric: &mut NumericContext,
    budget: &mut Budget,
) -> Result<BTreeMap<Address, BurnAmount>, LedgerError> {
    values
        .iter()
        .map(|(address, value)| {
            let literal = numeric.literal(&value.exact_string(budget)?)?;
            Ok((address.clone(), numeric.burn(&literal, unit)?))
        })
        .collect()
}
