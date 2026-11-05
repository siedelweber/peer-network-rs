use pn_secret_home::{Error, Protection, Staging};

/// Public acquisition refuses undeclared zero and conflicting budgets, and
/// consumes imported staging without exposing a byte accessor or signing API.
/// ´claim:crypto:home-public-boundary-requires-declared-budget´
/// ´test:integration:declared-budget´
#[test]
fn declared_budget() {
    assert_eq!(Protection::establish(0).unwrap_err(), Error::Budget);
    let protection = Protection::establish(65_536).unwrap();
    assert_eq!(Protection::establish(32_768).unwrap_err(), Error::Budget);
    let mut bytes = [0x92; 32];
    let home = protection.import(&mut Staging::acquire(&mut bytes)).unwrap();
    assert_eq!(bytes, [0; 32]);
    assert_eq!(format!("{home:?}"), "Home([REDACTED])");
}
