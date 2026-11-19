//! Storage-v1 projections compared in place with the pinned publication's validated spans.
//! (´[ROOT-amend:storage:admitted-correspondence]´)
use super::spans::Item;
use super::{Error, StorageError, decimal};

fn require(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(StorageError::CorruptHistory.into())
    }
}
fn same(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    require(a.bytes() == b.bytes())
}
fn number(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    require(a.unsigned()? == decimal(b.text()?)?)
}
fn pair(a: Item<'_>, b: Item<'_>, compare: impl Fn(Item<'_>, Item<'_>) -> Result<(), Error>) -> Result<(), Error> {
    let mut left = a.children()?;
    let mut right = b.children()?;
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ok(()),
            (Some(a), Some(b)) => compare(a, b)?,
            _ => return Err(StorageError::CorruptHistory.into()),
        }
    }
}
fn optional(a: Item<'_>, b: Item<'_>, compare: impl FnOnce(Item<'_>, Item<'_>) -> Result<(), Error>) -> Result<(), Error> {
    if a.null() || b.null() {
        require(a.null() && b.null())
    } else {
        compare(a, b)
    }
}
fn rational(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    let text = a.text()?;
    b.array(2)?;
    let numerator = b.field(0)?.text()?;
    let denominator = b.field(1)?.text()?;
    require(if denominator == "1" {
        text == numerator
    } else {
        text.strip_prefix(numerator).and_then(|tail| tail.strip_prefix('/')) == Some(denominator)
    })
}
fn amount(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(2)?;
    b.array(2)?;
    rational(a.field(0)?, b.field(0)?)?;
    same(a.field(1)?, b.field(1)?)
}
fn string_set(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    let mut previous = None;
    let mut count = 0usize;
    for value in a.children()? {
        let text = value.text()?;
        require(previous.is_none_or(|prior| prior < text))?;
        require(b.children()?.filter(|v| v.text().is_ok_and(|other| other == text)).count() == 1)?;
        previous = Some(text);
        count += 1;
    }
    require(count == b.children()?.count())
}
fn amounts(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    let mut previous = None;
    let mut count = 0usize;
    for value in a.children()? {
        value.array(2)?;
        let key = value.field(0)?.text()?;
        require(previous.is_none_or(|prior| prior < key))?;
        let mut entries = b.children()?;
        let mut found = None;
        while let Some(candidate) = entries.next() {
            let entry = entries.next().ok_or(StorageError::CorruptHistory)?;
            if candidate.text()? == key {
                require(found.is_none())?;
                found = Some(entry);
            }
        }
        amount(value.field(1)?, found.ok_or(StorageError::CorruptHistory)?)?;
        previous = Some(key);
        count += 1;
    }
    require(count.checked_mul(2) == Some(b.children()?.count()))
}
fn tag(a: Item<'_>, b: Item<'_>, names: &[&str]) -> Result<(), Error> {
    let index = usize::try_from(b.field(0)?.unsigned()?).map_err(|_| StorageError::CorruptHistory)?;
    require(names.get(index).is_some_and(|name| a.text().is_ok_and(|text| text == *name)))
}
pub(super) fn policy(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(13)?;
    b.array(13)?;
    for index in 0..13 {
        match index {
            3 | 4 | 12 => number(a.field(index)?, b.field(index)?)?,
            9 => tag(
                a.field(index)?,
                b.field(index)?,
                &["complete-list", "public-commitment", "whole-prefix"],
            )?,
            10 => tag(a.field(index)?, b.field(index)?, &["first-valid", "unique-per-index"])?,
            _ => same(a.field(index)?, b.field(index)?)?,
        }
    }
    Ok(())
}
pub(super) fn burn(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(9)?;
    b.array(9)?;
    for index in 0..3 {
        same(a.field(index)?, b.field(index)?)?;
    }
    number(a.field(3)?, b.field(3)?)?;
    string_set(a.field(4)?, b.field(4)?)?;
    amounts(a.field(5)?, b.field(5)?)?;
    optional(a.field(6)?, b.field(6)?, |a, b| {
        a.array(3)?;
        b.array(3)?;
        amount(a.field(0)?, b.field(0)?)?;
        same(a.field(1)?, b.field(1)?)?;
        same(a.field(2)?, b.field(2)?)
    })?;
    optional(a.field(7)?, b.field(7)?, |a, b| {
        a.array(4)?;
        b.array(4)?;
        rational(a.field(0)?, b.field(0)?)?;
        for index in 1..4 {
            same(a.field(index)?, b.field(index)?)?;
        }
        Ok(())
    })?;
    evidence(a.field(8)?, b.field(8)?)
}
fn evidence(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(7)?;
    b.array(7)?;
    for index in [0, 1, 3, 4] {
        same(a.field(index)?, b.field(index)?)?;
    }
    optional(a.field(2)?, b.field(2)?, number)?;
    optional(a.field(5)?, b.field(5)?, |a, b| {
        pair(a, b, |a, b| {
            a.array(3)?;
            b.array(3)?;
            rational(a.field(0)?, b.field(0)?)?;
            same(a.field(1)?, b.field(1)?)?;
            same(a.field(2)?, b.field(2)?)
        })
    })?;
    optional(a.field(6)?, b.field(6)?, |a, b| {
        tag(a.field(0)?, b, &["bound", "absent"])?;
        match b.field(0)?.unsigned()? {
            0 => {
                a.array(3)?;
                b.array(3)?;
                amount(a.field(1)?, b.field(1)?)?;
                same(a.field(2)?, b.field(2)?)
            }
            1 => {
                a.array(2)?;
                b.array(2)?;
                same(a.field(1)?, b.field(1)?)
            }
            _ => Err(StorageError::CorruptHistory.into()),
        }
    })
}
fn acceptance(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    tag(a.field(0)?, b, &["complete-list", "commitment", "whole-prefix"])?;
    match b.field(0)?.unsigned()? {
        0 => {
            a.array(2)?;
            b.array(2)?;
            string_set(a.field(1)?, b.field(1)?)
        }
        1 => {
            a.array(3)?;
            b.array(3)?;
            same(a.field(1)?, b.field(1)?)?;
            pair(a.field(2)?, b.field(2)?, |a, b| {
                a.array(2)?;
                b.array(2)?;
                string_set(a.field(0)?, b.field(0)?)?;
                same(a.field(1)?, b.field(1)?)
            })
        }
        2 => {
            a.array(1)?;
            b.array(1)?;
            Ok(())
        }
        _ => Err(StorageError::CorruptHistory.into()),
    }
}
fn marker(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(11)?;
    b.array(11)?;
    for index in 0..5 {
        same(a.field(index)?, b.field(index)?)?;
    }
    number(a.field(5)?, b.field(5)?)?;
    number(a.field(6)?, b.field(6)?)?;
    optional(a.field(7)?, b.field(7)?, number)?;
    string_set(a.field(8)?, b.field(8)?)?;
    acceptance(a.field(9)?, b.field(9)?)?;
    optional(a.field(10)?, b.field(10)?, amounts)
}
fn record(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(5)?;
    b.array(5)?;
    for index in [0, 1, 2, 4] {
        same(a.field(index)?, b.field(index)?)?;
    }
    amount(a.field(3)?, b.field(3)?)
}
pub(super) fn disclosure(a: Item<'_>, history: Item<'_>, p: Item<'_>, publication: Item<'_>) -> Result<(), Error> {
    a.array(5)?;
    history.array(3)?;
    same(a.field(0)?, history.field(0)?)?;
    let mut previous = None;
    let mut count = 0;
    for entry in a.field(1)?.children()? {
        let id = entry.field(0)?.text()?;
        require(previous.is_none_or(|prior| prior < id))?;
        let mut candidates = history
            .field(1)?
            .children()?
            .filter(|v| v.field(0).and_then(Item::text).is_ok_and(|value| value == id));
        record(entry, candidates.next().ok_or(StorageError::CorruptHistory)?)?;
        require(candidates.next().is_none())?;
        previous = Some(id);
        count += 1;
    }
    require(count == history.field(1)?.children()?.count())?;
    let mut previous = None;
    count = 0;
    for entry in a.field(2)?.children()? {
        let at = entry.field(6)?.unsigned()?;
        require(previous.is_none_or(|prior| prior < at))?;
        let mut candidates = history.field(2)?.children()?.filter(|v| {
            v.field(6)
                .and_then(Item::text)
                .and_then(decimal)
                .is_ok_and(|value| value == at)
        });
        marker(entry, candidates.next().ok_or(StorageError::CorruptHistory)?)?;
        require(candidates.next().is_none())?;
        previous = Some(at);
        count += 1;
    }
    require(count == history.field(2)?.children()?.count())?;
    policy(a.field(3)?, p)?;
    burn(a.field(4)?, publication)
}

pub(super) fn recognition(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(4)?;
    b.array(3)?;
    same(a.field(0)?, b.field(0)?)?;
    require(a.field(3)?.text()? == "unsettled")?;
    pair(a.field(1)?, b.field(1)?, |a, b| {
        a.array(3)?;
        b.array(3)?;
        marker(a.field(0)?, b.field(0)?)?;
        string_set(a.field(1)?, b.field(1)?)?;
        let mut count = 0;
        let mut previous = None;
        for entry in a.field(2)?.children()? {
            let id = entry.field(1)?.text()?;
            require(previous.is_none_or(|prior| prior < id))?;
            let mut map = b.field(2)?.children()?;
            let mut found = None;
            while let Some(key) = map.next() {
                let value = map.next().ok_or(StorageError::CorruptHistory)?;
                if key.text()? == id {
                    require(found.is_none())?;
                    found = Some(value);
                }
            }
            record(entry, found.ok_or(StorageError::CorruptHistory)?)?;
            previous = Some(id);
            count += 1;
        }
        require(count * 2 == b.field(2)?.children()?.count())
    })?;
    optional(a.field(2)?, b.field(2)?, |a, b| {
        a.array(3)?;
        b.array(3)?;
        optional(a.field(0)?, b.field(0)?, marker)?;
        tag(
            a.field(1)?,
            b.field(1)?,
            &[
                "policy-selection",
                "policy-binding",
                "deployment-binding",
                "policy-digest",
                "unsupported-policy-recipe",
                "publication",
                "evidence-binding",
                "sample-coverage",
                "units",
                "bootstrap",
                "policy",
                "buffer",
                "verifier",
                "record-identity",
                "history-policy",
                "history-position",
                "initial",
                "succession",
                "missing-lineage",
                "regressed-lineage",
                "encoding",
                "missing-opening",
                "ambiguous-opening",
                "invalid-opening",
                "regressed-acceptance",
                "out-of-lineage",
                "invalid-member",
                "inconsistent-alias",
            ],
        )?;
        pair(a.field(2)?, b.field(2)?, marker)
    })
}

pub(super) fn constants(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(12)?;
    b.array(11)?;
    let left = a.field(0)?.array(3)?;
    let right = b.field(0)?.array(3)?;
    same(left.field(0)?, right.field(0)?)?;
    same(left.field(1)?, right.field(1)?)?;
    number(left.field(2)?, right.field(2)?)?;
    tag(a.field(1)?, b.field(1)?, &["rational-3/37", "ridge-image"])?;
    let left = a.field(2)?.array(3)?;
    let right = b.field(2)?.array(2)?;
    same(left.field(0)?, right.field(0)?)?;
    rational(left.field(1)?, right.field(1)?.field(0)?)?;
    same(left.field(2)?, right.field(1)?.field(1)?)?;
    for index in [3, 4, 8, 9, 10] {
        same(a.field(index)?, b.field(index)?)?;
    }
    pair(a.field(5)?, b.field(5)?, definition)?;
    same(a.field(6)?, b.field(6)?)?;
    same(a.field(7)?, b.field(7)?)?;
    let source = a.field(11)?.array(4)?;
    require(source.field(0)?.text()? == "expression" && source.field(1)?.text()? == "structural-floor")?;
    let (expression, label) = match b.field(1)?.field(0)?.unsigned()? {
        0 => ("3/37", "case:epoch:safety-wall-floor-rational-floor"),
        1 => (
            "p_ridge/(1-p_ridge); p_ridge is the defining ridge real",
            "case:epoch:safety-wall-floor-ridge-floor",
        ),
        _ => return Err(StorageError::CorruptHistory.into()),
    };
    require(source.field(2)?.text()? == expression && source.field(3)?.text()? == label)
}
fn definition(a: Item<'_>, b: Item<'_>) -> Result<(), Error> {
    a.array(4)?;
    tag(a.field(0)?, b, &["literal", "expression"])?;
    same(a.field(1)?, b.field(1)?)?;
    match b.field(0)?.unsigned()? {
        0 => {
            b.array(3)?;
            same(a.field(2)?, b.field(2)?.field(0)?)?;
            rational(a.field(3)?, b.field(2)?.field(1)?)
        }
        1 => {
            b.array(4)?;
            same(a.field(2)?, b.field(2)?)?;
            same(a.field(3)?, b.field(3)?)
        }
        _ => Err(StorageError::CorruptHistory.into()),
    }
}

pub(super) fn marker_identity_match(a: Item<'_>, b: Item<'_>) -> Result<bool, Error> {
    a.array(11)?;
    b.array(11)?;
    let mut same = true;
    for index in 1..9 {
        same &= a.field(index)?.bytes() == b.field(index)?.bytes();
    }
    let a = a.field(9)?;
    let b = b.field(9)?;
    same &= a.field(0)?.bytes() == b.field(0)?.bytes();
    match a.field(0)?.unsigned()? {
        0 | 1 => Ok(same && a.field(1)?.bytes() == b.field(1)?.bytes()),
        2 => Ok(same),
        _ => Err(StorageError::CorruptHistory.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Meter, ReadBudget, Usage, spans::Validated};
    use super::*;
    use pn_interchange::{Array, Value};
    use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};

    /// Claim: The server reader's in-place rational comparison accepts the records carrier's canonical exact spelling and refuses a distinct respelling for seven public rational pairs at its private comparison boundary, without claiming an end-to-end damaged-store read.
    /// ´claim:history:tree-server-rational-spelling´
    /// ´test:unit:tree-server-rational-spelling´
    #[test]
    fn tree_server_rational_spelling() {
        let mut context = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
        for (numerator, denominator, alternate) in [
            ("23", "11", "46/22"),
            ("0", "1", "0/1"),
            ("-3", "7", "-6/14"),
            ("2", "1", "2/1"),
            ("1", "3", "2/6"),
            ("-2", "1", "-2/1"),
            ("123456789012345678901234567890", "1", "123456789012345678901234567890/1"),
        ] {
            let joined = format!("{numerator}/{denominator}");
            let literal = context.literal(&joined).unwrap();
            let canonical = literal.exact();
            assert_eq!(
                context.literal(alternate).unwrap().exact(),
                canonical,
                "the respelling retains the exact value"
            );
            assert_ne!(canonical, alternate, "the negative input changes the stored spelling");
            let pair = Value::Array(Array::new([
                Value::Text(numerator.to_owned().into()),
                Value::Text(denominator.to_owned().into()),
            ]))
            .to_canonical_bytes();
            for (text, accepted) in [(canonical, true), (alternate, false)] {
                let bytes = Value::Text(text.to_owned().into()).to_canonical_bytes();
                let mut meter = Meter {
                    limit: ReadBudget {
                        rows: 0,
                        bytes: 1_000_000,
                    },
                    used: Usage::default(),
                };
                let stored = Validated::new(&bytes, &mut meter).unwrap();
                let published = Validated::new(&pair, &mut meter).unwrap();
                let result = rational(stored.root().unwrap(), published.root().unwrap());
                if accepted {
                    assert!(result.is_ok(), "the writer's canonical spelling compares equal");
                } else {
                    assert!(
                        matches!(result, Err(Error::Storage(StorageError::CorruptHistory))),
                        "a respelled rational refuses at the comparison"
                    );
                }
            }
        }
    }
}
