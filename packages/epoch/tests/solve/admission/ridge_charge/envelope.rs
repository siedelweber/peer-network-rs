use super::*;

#[derive(Debug)]
struct Permissive;
impl pn_records::ridge::ChargeVerifier for Permissive {
    fn replay(&self, _: &ChargeEvidence) -> Result<(), NumericError> {
        Ok(())
    }
}

fn unchecked(evidence: &ChargeEvidence) -> Result<pn_records::numerics::ChargedPrice, NumericError> {
    let mut numeric = joined::numeric();
    let (_, edition, _) = common::fixture();
    let wall = numeric.literal(NumberId::NumbersAdmissionWall.value()).unwrap();
    let wall = numeric.computed(&wall).unwrap();
    numeric.charged_price_with_ridge(&wall, &edition.numeraire, evidence, &Permissive)
}

/// Claim: With a permissive test verifier, records refuses altered schema, bracket, cover cell and image envelopes; epoch ledger compilation independently refuses a price formed from a changed query precision. These finite controls establish explicit verifier selection at consumption, not a sealed records authority.
/// ´claim:admission:ridge-consumption-selects-admitted-replay´
/// ´test:integration:ridge-envelope-consumption´
#[test]
fn ridge_envelope_consumption() {
    let evidence = proof(NumberId::NumbersRidgeCertificatePrecision);
    assert!(unchecked(&evidence).is_ok());
    let mut changed = evidence.clone();
    changed.analytic_premises = "unknown-ridge-premises".into();
    assert_eq!(unchecked(&changed), Err(NumericError::RidgeDefinition));
    changed = evidence.clone();
    changed.record.input.definition.schema = "different-record-input".into();
    assert_eq!(unchecked(&changed), Err(NumericError::RidgeEvidence));
    changed = evidence.clone();
    changed.input.definition.schema = "unknown-ridge".into();
    changed.record.input = changed.input.clone();
    assert_eq!(unchecked(&changed), Err(NumericError::RidgeDefinition));
    changed = evidence.clone();
    changed.input.bracket.lower = "0".into();
    changed.record.input = changed.input.clone();
    assert_eq!(unchecked(&changed), Err(NumericError::RidgeEvidence));
    changed = evidence.clone();
    changed.record.cells[0].lower = changed.record.cells[0].upper.clone();
    assert_eq!(unchecked(&changed), Err(NumericError::RidgeEvidence));
    changed = evidence.clone();
    changed.record.image.as_mut().unwrap().lower = "0".into();
    assert_eq!(unchecked(&changed), Err(NumericError::RidgeEvidence));
    changed = evidence.clone();
    changed.record.queries[0].precision += 1;
    let unchecked_price = unchecked(&changed).unwrap();
    let context = ridge_candidate(&evidence);
    let causes = &context.input().causes;
    assert!(matches!(
        pn_epoch::ledger::compile_ledger(
            &causes.inputs,
            &[unchecked_price],
            &causes.markers,
            &causes.history,
            &joined::Verifier,
            &mut joined::numeric(),
            Limits::default(),
        ),
        Err(pn_epoch::ledger::LedgerError::Numeric(NumericError::RidgeEvidence))
    ));
}
