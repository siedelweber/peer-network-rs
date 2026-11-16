//! Complete selected-use and debit correspondence on borrowed strict-validation spans.
//! (´[ROOT-amend:storage:admitted-correspondence]´)
use super::{
    EpochScope, Error, Family, Header, Meter, Scope, ServerDebit, ServerSelection, StorageError, content, decimal, fields,
    spans::{Item, Validated},
};
use std::fmt::Write;

struct Uses<'a, 'm> {
    scope: &'a EpochScope,
    header: &'a Header,
    document: &'a Validated<'a>,
    frame: Item<'a>,
    selections: &'a [ServerSelection],
    found: Vec<bool>,
    meter: &'m mut Meter,
}

pub(super) fn validate(
    scope: &EpochScope,
    header: &Header,
    document: &Validated<'_>,
    selections: &[ServerSelection],
    debits: &[ServerDebit],
    meter: &mut Meter,
) -> Result<(), Error> {
    let root = document.root()?;
    if root.children()?.count() != 18
        || root.map_value(0)?.text()? != "org.peer-network.test.publication"
        || root.map_value(1)?.bytes() != [0x83, 1, 0, 0]
    {
        return Err(StorageError::CorruptHistory.into());
    }
    let reproductions = root.map_value(8)?.array(4)?.field(3)?;
    let first = reproductions.children()?.next().ok_or(StorageError::CorruptHistory)?;
    let mut found = Vec::new();
    meter.reserve(&mut found, selections.len())?;
    found.resize(selections.len(), false);
    let mut uses = Uses {
        scope,
        header,
        document,
        frame: first,
        selections,
        found,
        meter,
    };
    for (index, frame) in reproductions.children()?.enumerate() {
        uses.frame = frame.array(9)?;
        uses.frame_uses(index)?;
    }
    if uses.found.iter().any(|found| !found) {
        return Err(StorageError::CorruptHistory.into());
    }
    let last = reproductions.children()?.last().ok_or(StorageError::CorruptHistory)?;
    let policy = last.field(5)?;
    let history = last.field(6)?;
    if [
        history.field(0)?.text()?,
        policy.field(0)?.text()?,
        policy.field(1)?.text()?,
        policy.field(2)?.text()?,
    ] != fields(scope)
        || decimal(last.field(2)?.field(0)?.text()?)? != header.depth
    {
        return Err(StorageError::CorruptHistory.into());
    }
    debit_values(root, debits)
}

impl<'a> Uses<'a, '_> {
    fn key(&self, suffix: &[&str], observation: bool) -> Result<Scope, Error> {
        let mut key = Scope {
            bytes: [0; 1024],
            len: 0,
        };
        write!(key, "{}:", 8 + suffix.len() + usize::from(observation)).map_err(|_| StorageError::CorruptHistory)?;
        let mut append =
            |field: &str| write!(key, "{}:{field}", field.len()).map_err(|_| Error::from(StorageError::CorruptHistory));
        for field in fields(self.scope) {
            append(field)?;
        }
        let hex = hex(self.header.identity);
        if observation {
            append(std::str::from_utf8(&hex).map_err(|_| StorageError::CorruptHistory)?)?;
        }
        append(self.frame.field(6)?.field(0)?.text()?)?;
        let policy = self.frame.field(5)?;
        for index in 0..3 {
            append(policy.field(index)?.text()?)?;
        }
        for field in suffix {
            append(field)?;
        }
        Ok(key)
    }

    fn expected(
        &mut self,
        family: Family,
        suffix: &[&str],
        coordinate: u64,
        edition: &str,
        interval: (u64, u64),
        compare: impl FnOnce(Item<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let key = self.key(suffix, !matches!(family, Family::Rule | Family::Constants))?;
        let mut matching = self.selections.iter().enumerate().filter(|(_, selected)| {
            selected.use_.selected_at == coordinate
                && selected.use_.version.family == family
                && selected.use_.version.key == key.text().unwrap_or("")
                && selected.use_.version.edition == edition
        });
        let (index, selected) = matching.next().ok_or(StorageError::CorruptHistory)?;
        if matching.next().is_some()
            || selected.use_.version.announced_at != interval.0
            || selected.use_.version.opens_at != interval.1
        {
            return Err(StorageError::CorruptHistory.into());
        }
        let payload = selected.use_.version.payload.as_ref().ok_or(StorageError::CorruptHistory)?;
        let validated = Validated::new(&payload.bytes, self.meter)?;
        compare(validated.root()?.array(3)?.field(2)?)?;
        self.found[index] = true;
        Ok(())
    }

    fn declaration(&self, id: Item<'_>) -> Result<Option<Item<'a>>, Error> {
        let mut declarations = self
            .document
            .root()?
            .map_value(8)?
            .field(0)?
            .children()?
            .filter(|d| d.field(0).is_ok_and(|candidate| candidate.bytes() == id.bytes()));
        let declaration = declarations.next();
        if declarations.next().is_some() {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(declaration)
    }

    fn rule(&mut self, id: Item<'_>, at: u64) -> Result<(), Error> {
        let Some(declaration) = self.declaration(id)? else {
            return Ok(());
        };
        let namespace = id.field(0)?.text()?;
        let name = id.field(1)?.text()?;
        let edition = id.field(2)?.text()?;
        let announced = decimal(declaration.field(1)?.text()?)?;
        let opens = decimal(declaration.field(2)?.text()?)?;
        let bytes = declaration.bytes();
        self.expected(
            Family::Rule,
            &["declaration", namespace, name],
            at,
            edition,
            (announced, opens),
            |body| {
                if body.blob()? == bytes {
                    Ok(())
                } else {
                    Err(StorageError::CorruptHistory.into())
                }
            },
        )
    }

    fn effective(&mut self, namespace: &str, name: &str, at: u64) -> Result<(), Error> {
        let mut selected = None;
        for declaration in self.document.root()?.map_value(8)?.field(0)?.children()? {
            let id = declaration.field(0)?;
            if id.field(0)?.text()? != namespace || id.field(1)?.text()? != name {
                continue;
            }
            let effective = decimal(declaration.field(2)?.text()?)?;
            if effective <= at {
                if selected.is_some_and(|(prior, _)| prior == effective) {
                    return Err(StorageError::CorruptHistory.into());
                }
                if selected.is_none_or(|(prior, _)| prior < effective) {
                    selected = Some((effective, id));
                }
            }
        }
        self.rule(selected.ok_or(StorageError::CorruptHistory)?.1, at)
    }

    fn parameters(&mut self, parameters: Item<'_>) -> Result<(), Error> {
        let at = decimal(parameters.field(0)?.text()?)?;
        self.rule(parameters.field(1)?, at)?;
        for profile in parameters.field(3)?.children()? {
            self.rule(profile.field(2)?, at)?;
        }
        Ok(())
    }
    fn inputs(&mut self, inputs: Item<'_>) -> Result<(), Error> {
        let parameters = inputs.field(0)?;
        self.parameters(parameters)?;
        let id = parameters.field(1)?;
        let declaration = self.declaration(id)?.ok_or(StorageError::CorruptHistory)?;
        let announced = decimal(declaration.field(1)?.text()?)?;
        let opens = decimal(declaration.field(2)?.text()?)?;
        self.expected(
            Family::Constants,
            &["constants", id.field(0)?.text()?, id.field(1)?.text()?],
            decimal(parameters.field(0)?.text()?)?,
            id.field(2)?.text()?,
            (announced, opens),
            |body| content::constants(body, inputs.field(1)?),
        )
    }
    fn procedure(&mut self, procedure: Item<'_>) -> Result<(), Error> {
        self.rule(procedure.field(0)?, decimal(procedure.field(1)?.text()?)?)
    }
    fn price(&mut self, price: Item<'_>) -> Result<(), Error> {
        let ridge = price.field(4)?;
        if !ridge.null() {
            self.procedure(ridge.field(1)?)?;
        }
        Ok(())
    }
    fn standing(&mut self, standing: Item<'_>) -> Result<(), Error> {
        for round in standing.field(1)?.children()? {
            for map in round.field(0)?.children()?.chain(std::iter::once(round.field(1)?)) {
                self.rule(map.field(0)?, decimal(map.field(1)?.text()?)?)?;
            }
        }
        Ok(())
    }
    fn schedule(&mut self, schedule: Item<'_>) -> Result<(), Error> {
        for publication in schedule.field(2)?.children()? {
            self.procedure(publication.field(3)?.field(3)?.field(0)?)?;
        }
        Ok(())
    }
    fn frame_uses(&mut self, index: usize) -> Result<(), Error> {
        let frame = self.frame;
        let genesis = decimal(frame.field(5)?.field(4)?.text()?)?;
        self.effective("marker", "policy", genesis)?;
        self.effective("deployment", "genesis", genesis)?;
        self.parameters(frame.field(2)?)?;
        for binding in frame.field(8)?.children()? {
            self.inputs(binding.field(2)?)?;
            self.price(binding.field(3)?)?;
        }
        self.procedure(frame.field(4)?.field(0)?)?;
        self.price(frame.field(3)?)?;
        let root = self.document.root()?;
        let mut debits = root.map_value(3)?.field(index)?.field(3)?.children()?;
        while debits.next().is_some() {
            self.price(debits.next().ok_or(StorageError::CorruptHistory)?.field(0)?)?;
        }
        let base = root.map_value(4)?.field(index)?.field(3)?;
        self.rule(base.field(1)?, decimal(base.field(0)?.text()?)?)?;
        let standings = root.map_value(6)?.field(index)?;
        self.standing(standings.field(0)?)?;
        let standing = standings.field(1)?.field(2)?;
        if !standing.null() {
            self.standing(standing)?;
        }
        let closures = root.map_value(7)?.field(index)?;
        self.schedule(closures.field(1)?)?;
        self.schedule(closures.field(2)?)?;
        self.observations()
    }
    fn observation(
        &mut self,
        family: Family,
        suffix: &[&str],
        compare: impl FnOnce(Item<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let encoded = hex(self.header.identity);
        let edition = std::str::from_utf8(&encoded).map_err(|_| StorageError::CorruptHistory)?;
        self.expected(
            family,
            suffix,
            self.header.depth,
            edition,
            (self.header.depth, self.header.depth),
            compare,
        )
    }
    fn observations(&mut self) -> Result<(), Error> {
        let frame = self.frame;
        let publication = frame.field(1)?;
        let policy = frame.field(5)?;
        let history = frame.field(6)?;
        let recognition = frame.field(7)?;
        let boundary = frame.field(2)?.field(0)?.text()?;
        let address = publication.field(0)?.text()?;
        let edition = publication.field(1)?.text()?;
        let convention = publication.field(2)?.text()?;
        self.observation(
            Family::MarkerPolicy,
            &["policy-observation", boundary, address, edition, convention],
            |body| {
                body.array(2)?;
                content::policy(body.field(0)?, policy)?;
                content::burn(body.field(1)?, publication)
            },
        )?;
        self.observation(
            Family::BurnPublication,
            &["burn", boundary, address, edition, convention],
            |body| content::burn(body, publication),
        )?;
        let basis = recognition.field(0)?.array(6)?;
        let members = [
            basis.field(0)?.text()?,
            basis.field(1)?.text()?,
            basis.field(2)?.text()?,
            basis.field(3)?.text()?,
            basis.field(4)?.text()?,
            basis.field(5)?.text()?,
        ];
        self.observation(
            Family::Lineage,
            &[
                "lineage", boundary, members[0], members[1], members[2], members[3], members[4], members[5],
            ],
            |body| content::disclosure(body, history, policy, publication),
        )?;
        self.observation(
            Family::UnsettledRecognition,
            &[
                "recognition",
                boundary,
                members[0],
                members[1],
                members[2],
                members[3],
                members[4],
                members[5],
            ],
            |body| {
                body.array(4)?;
                content::disclosure(body.field(2)?, history, policy, publication)?;
                content::recognition(body.field(3)?, recognition)
            },
        )
    }
}

fn hex(identity: [u8; 32]) -> [u8; 64] {
    let mut result = [0; 64];
    for (pair, byte) in result.as_chunks_mut::<2>().0.iter_mut().zip(identity) {
        pair[0] = b"0123456789abcdef"[usize::from(byte >> 4)];
        pair[1] = b"0123456789abcdef"[usize::from(byte & 15)];
    }
    result
}

fn debit_values(root: Item<'_>, debits: &[ServerDebit]) -> Result<(), Error> {
    let ledger = root.map_value(3)?.children()?.last().ok_or(StorageError::CorruptHistory)?;
    let mut entries = ledger.field(3)?.children()?;
    let mut count = 0;
    while let Some(key) = entries.next() {
        key.array(3)?;
        let value = entries.next().ok_or(StorageError::CorruptHistory)?;
        let author = key.field(0)?.text()?;
        let sequence = decimal(key.field(1)?.text()?)?;
        let family = key.field(2)?.text()?;
        let mut matching = debits
            .iter()
            .filter(|debit| debit.act.author == author && debit.act.sequence == sequence && debit.act.family == family);
        let found = matching.next().ok_or(StorageError::CorruptHistory)?;
        if matching.next().is_some() || found.bytes != value.bytes() {
            return Err(StorageError::CorruptHistory.into());
        }
        count += 1;
    }
    if count != debits.len() {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(())
}

fn last<'a>(document: &'a Validated<'a>) -> Result<Item<'a>, Error> {
    document
        .root()?
        .map_value(8)?
        .field(3)?
        .children()?
        .last()
        .ok_or(StorageError::CorruptHistory.into())
}
fn genesis<'a>(document: &'a Validated<'a>) -> Result<Item<'a>, Error> {
    let mut declarations = document.root()?.map_value(8)?.field(0)?.children()?.filter(|d| {
        d.field(0).is_ok_and(|id| {
            id.field(0).and_then(Item::text) == Ok("deployment") && id.field(1).and_then(Item::text) == Ok("genesis")
        })
    });
    let result = declarations.next().ok_or(StorageError::CorruptHistory)?;
    if declarations.next().is_some() {
        return Err(StorageError::CorruptHistory.into());
    }
    Ok(result)
}
fn ensure(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(StorageError::CorruptHistory.into())
    }
}
pub(super) fn context(a: &Validated<'_>, b: &Validated<'_>) -> Result<(), Error> {
    ensure(genesis(a)?.bytes() == genesis(b)?.bytes())?;
    let a = last(a)?;
    let b = last(b)?;
    ensure(a.field(5)?.bytes() == b.field(5)?.bytes())?;
    let am = a.field(7)?.field(1)?.children()?.next().ok_or(StorageError::CorruptHistory)?;
    let bm = b.field(7)?.field(1)?.children()?.next().ok_or(StorageError::CorruptHistory)?;
    content::marker_identity(am.field(0)?, bm.field(0)?)?;
    ensure(am.field(1)?.children()?.next().is_none() && bm.field(1)?.children()?.next().is_none())?;
    lineage(a.field(6)?, b.field(6)?, am.field(0)?.field(8)?)
}
fn lineage(a: Item<'_>, b: Item<'_>, members: Item<'_>) -> Result<(), Error> {
    for member in members.children()? {
        let name = member.text()?;
        let ar = find_record(a, name)?;
        let br = find_record(b, name)?;
        for index in 0..4 {
            ensure(ar.field(index)?.bytes() == br.field(index)?.bytes())?;
        }
    }
    Ok(())
}
fn find_record<'a>(history: Item<'a>, name: &str) -> Result<Item<'a>, Error> {
    let mut found = history
        .field(1)?
        .children()?
        .filter(|record| record.field(0).and_then(Item::text).is_ok_and(|id| id == name));
    let record = found.next().ok_or(StorageError::CorruptHistory)?;
    ensure(found.next().is_none())?;
    Ok(record)
}
pub(super) fn extends(a: &Validated<'_>, b: &Validated<'_>) -> Result<(), Error> {
    context(a, b)?;
    let a = last(a)?;
    let b = last(b)?;
    let mut bindings = a.field(8)?.children()?;
    for prior in b.field(8)?.children()? {
        let current = bindings.next().ok_or(StorageError::CorruptHistory)?;
        content::marker_identity(current.field(0)?, prior.field(0)?)?;
        content::marker_identity(current.field(1)?, prior.field(1)?)?;
        for index in 2..5 {
            ensure(current.field(index)?.bytes() == prior.field(index)?.bytes())?;
        }
    }
    let previous = terminal(b)?;
    let current = terminal(a)?;
    let old = previous.field(0)?;
    let new = current.field(0)?;
    ensure(decimal(old.field(5)?.text()?)?.checked_add(1) == Some(decimal(new.field(5)?.text()?)?))?;
    ensure(new.field(7)?.bytes() == old.field(6)?.bytes())?;
    ensure(decimal(new.field(6)?.text()?)? > decimal(old.field(6)?.text()?)?)?;
    let disclosed = a
        .field(7)?
        .field(1)?
        .children()?
        .find(|m| {
            m.field(0)
                .and_then(|m| m.field(5))
                .is_ok_and(|index| old.field(5).is_ok_and(|expected| index.bytes() == expected.bytes()))
        })
        .ok_or(StorageError::CorruptHistory)?;
    content::marker_identity(disclosed.field(0)?, old)?;
    ensure(disclosed.field(1)?.bytes() == previous.field(1)?.bytes())?;
    for (base, extended) in [(old.field(8)?, new.field(8)?), (previous.field(1)?, current.field(1)?)] {
        for value in base.children()? {
            ensure(extended.children()?.any(|candidate| candidate.bytes() == value.bytes()))?;
        }
    }
    lineage(a.field(6)?, b.field(6)?, old.field(8)?)
}
pub(super) fn debit_origin(document: &Validated<'_>, debit: &ServerDebit) -> Result<(), Error> {
    let ledger = document
        .root()?
        .map_value(3)?
        .children()?
        .last()
        .ok_or(StorageError::CorruptHistory)?;
    let mut entries = ledger.field(3)?.children()?;
    let mut found = false;
    while let Some(key) = entries.next() {
        let value = entries.next().ok_or(StorageError::CorruptHistory)?;
        if key.field(0)?.text()? == debit.act.author
            && decimal(key.field(1)?.text()?)? == debit.act.sequence
            && key.field(2)?.text()? == debit.act.family
        {
            ensure(!found && value.bytes() == debit.bytes)?;
            found = true;
        }
    }
    ensure(found)
}

fn terminal(frame: Item<'_>) -> Result<Item<'_>, Error> {
    let boundary = frame.field(2)?.field(0)?;
    let mut found = frame.field(7)?.field(1)?.children()?.filter(|marker| {
        marker
            .field(0)
            .and_then(|m| m.field(5))
            .is_ok_and(|index| index.bytes() == boundary.bytes())
    });
    let result = found.next().ok_or(StorageError::CorruptHistory)?;
    ensure(found.next().is_none())?;
    Ok(result)
}
