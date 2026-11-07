pub(super) fn decode_control(
    bytes: &[u8],
    expected: &pn_epoch::publication::disclosures::Disclosure,
    numeric: &mut pn_records::numerics::NumericContext,
    limits: pn_epoch::publication::disclosures::Limits,
) -> Result<pn_epoch::publication::disclosures::Disclosure, pn_host::publication::Error> {
    let decoded = pn_host::publication::decode(bytes, numeric, limits)?;
    assert_eq!(&decoded, expected);
    Ok(decoded)
}
