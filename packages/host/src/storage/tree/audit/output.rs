//! Materialization of the audit's decided logical field tree.
//! (´[ROOT-amend:storage:tree-audit]´)

use super::{
    AuditFailure, AuditInventory, AuditMeter, AuditSite, Collected, LocationState, RawDebit, debit_location, generation_location,
    reference_location, result_location, scope_location, version_location,
};
use crate::storage::{Family, Version};
use pn_interchange::{Array, Bytes, Text, Value};

fn array<const N: usize>(fields: [Value; N], meter: &mut AuditMeter, site: AuditSite<'_>) -> Result<Value, AuditFailure> {
    let mut out = Vec::new();
    meter.reserve(&mut out, N, site)?;
    out.extend(fields);
    Ok(Value::Array(Array::take_reserved(&mut out)))
}

fn sequence(out: &mut Vec<Value>) -> Value {
    Value::Array(Array::take_reserved(out))
}

fn family(value: Family) -> Value {
    Value::Unsigned(match value {
        Family::Constants => 0,
        Family::Rule => 1,
        Family::MarkerPolicy => 2,
        Family::Lineage => 3,
        Family::BurnPublication => 4,
        Family::UnsettledRecognition => 5,
    })
}

fn text(s: &str, meter: &mut AuditMeter, site: AuditSite<'_>) -> Result<Value, AuditFailure> {
    let mut out = Vec::new();
    meter.reserve(&mut out, s.len(), site)?;
    out.extend_from_slice(s.as_bytes());
    let value = Text::take_reserved(&mut out).map_err(|_| meter.allocated(site))?;
    Ok(Value::Text(value))
}

fn bytes(s: &[u8], meter: &mut AuditMeter, site: AuditSite<'_>) -> Result<Value, AuditFailure> {
    let mut out = Vec::new();
    meter.reserve(&mut out, s.len(), site)?;
    out.extend_from_slice(s);
    let value = Bytes::take_reserved(&mut out).map_err(|_| meter.allocated(site))?;
    Ok(Value::Bytes(value))
}

fn version(version: &Version, meter: &mut AuditMeter, site: AuditSite<'_>) -> Result<Value, AuditFailure> {
    let payload = if let Some(payload) = &version.payload {
        let (digest, disclosure) = payload.commitments();
        let disclosure = disclosure.map(<[u8; 32]>::as_slice);
        array(
            [
                family(payload.family),
                bytes(payload.bytes(), meter, site)?,
                bytes(digest, meter, site)?,
                disclosure.map_or(Ok(Value::Null), |value| bytes(value, meter, site))?,
            ],
            meter,
            site,
        )?
    } else {
        Value::Null
    };
    array(
        [
            family(version.family),
            text(&version.key, meter, site)?,
            text(&version.edition, meter, site)?,
            Value::Unsigned(version.announced_at),
            Value::Unsigned(version.opens_at),
            payload,
        ],
        meter,
        site,
    )
}

fn count_overflow() -> AuditFailure {
    AuditMeter::refused_unavailable(crate::storage::StorageError::ReadLimit, LocationState::NotRead)
}

fn checked_sum(parts: &[usize]) -> Result<usize, AuditFailure> {
    parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(*part).ok_or_else(count_overflow))
}

fn counts(value: &Value) -> Result<(usize, usize), AuditFailure> {
    let mut slots = 1usize;
    let mut bytes = 0usize;
    match value {
        Value::Text(value) => bytes = value.as_str().len(),
        Value::Bytes(value) => bytes = value.as_slice().len(),
        Value::Array(value) => {
            for child in value.as_slice() {
                let (part_bytes, part_slots) = counts(child)?;
                bytes = bytes.checked_add(part_bytes).ok_or_else(count_overflow)?;
                slots = slots.checked_add(part_slots).ok_or_else(count_overflow)?;
            }
        }
        _ => {}
    }
    Ok((bytes, slots))
}

fn retain_entry(out: &mut Vec<Value>, entry: Value, meter: &mut AuditMeter, site: AuditSite<'_>) -> Result<(), AuditFailure> {
    let (bytes, items) = counts(&entry)?;
    // The complete invocation has already admitted these counters. Advance
    // them when this owned occurrence enters the retained inventory.
    meter.retain(bytes, items, site)?;
    out.push(entry);
    Ok(())
}

fn last_site<'a>(rows: &'a Collected<'_>) -> AuditSite<'a> {
    rows.results
        .last()
        .map(|row| result_location(row.scope, row.identity))
        .or_else(|| rows.scopes.last().map(|scope| scope_location(scope.scope)))
        .or_else(|| {
            rows.generations
                .last()
                .map(|generation| generation_location(generation, "pn_admission_generations", None))
        })
        .unwrap_or(AuditSite::NotRead)
}

#[derive(Default)]
struct Count {
    bytes: usize,
    items: usize,
}

impl Count {
    fn add(&mut self, bytes: usize, items: usize) -> Result<(), AuditFailure> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(count_overflow)?;
        self.items = self.items.checked_add(items).ok_or_else(count_overflow)?;
        Ok(())
    }
    fn version(&mut self, row: &Version) -> Result<(), AuditFailure> {
        self.add(checked_sum(&[row.key.len(), row.edition.len()])?, 7)?;
        if let Some(payload) = &row.payload {
            // The payload field already occupies one of Version's six slots.
            self.add(
                checked_sum(&[payload.bytes().len(), 32, payload.commitments().1.map_or(0, |_| 32)])?,
                4,
            )?;
        }
        Ok(())
    }
}

fn prospective_counts(
    rows: &Collected<'_>,
    parents: &[Option<usize>],
    children: &[Vec<usize>],
    debits: &[Vec<RawDebit<'_>>],
    contexts: &[Option<Value>],
    meter: &mut AuditMeter,
) -> Result<Count, AuditFailure> {
    let mut total = Count::default();
    total.add(0, 5)?;
    for generation in &rows.generations {
        total.add(checked_sum(&[generation.key.len(), generation.declaration.label.len()])?, 8)?;
        for version in &generation.versions {
            total.version(version)?;
        }
        for closure in &generation.closures {
            total.add(checked_sum(&[closure.key.len(), closure.edition.len()])?, 5)?;
        }
    }
    for generation in &rows.generations {
        for row in &generation.versions {
            total.add(generation.key.len(), 7)?;
            total.version(row)?;
        }
    }
    for row in &rows.results {
        for version in &row.content().observations {
            total.add(row.key.len(), 7)?;
            total.version(version)?;
        }
    }
    for (scope_at, scope) in rows.scopes.iter().enumerate() {
        meter.visit(scope_location(scope.scope))?;
        let context = contexts[scope_at]
            .as_ref()
            .ok_or_else(|| meter.refused(crate::storage::StorageError::CorruptHistory, scope_location(scope.scope)))?;
        let (context_bytes, context_items) = counts(context)?;
        total.add(
            checked_sum(&[scope.key.len(), context_bytes])?,
            checked_sum(&[4, context_items])?,
        )?;
        meter.visit(scope_location(scope.scope))?;
        let first = rows.results.partition_point(|row| row.key < scope.key);
        meter.visit(scope_location(scope.scope))?;
        let last = rows.results.partition_point(|row| row.key <= scope.key);
        for at in first..last {
            let row = &rows.results[at];
            meter.visit(result_location(row.scope, row.identity))?;
            if parents[at].is_none() {
                total.add(32, 1)?;
            }
            if children[at].is_empty() {
                total.add(32, 1)?;
            }
        }
    }
    for (at, row) in rows.results.iter().enumerate() {
        total.add(
            checked_sum(&[
                row.key.len(),
                32,
                row.parent.map_or(0, |_| 32),
                row.content().package.len(),
                row.label.len(),
            ])?,
            10,
        )?;
        for selection in &row.content().selections {
            total.add(32, 3)?;
            total.version(&selection.use_.version)?;
        }
        for debit in &debits[at] {
            let act = debit.act;
            total.add(checked_sum(&[act.author.len(), act.family.len(), 32, debit.bytes.len()])?, 7)?;
        }
    }
    Ok(total)
}

// Justified: The complete field table is emitted in one visible order after the capacity preflight.
#[allow(clippy::too_many_lines)]
pub(super) fn materialize(
    rows: &Collected<'_>,
    parents: &[Option<usize>],
    children: &[Vec<usize>],
    debits: &[Vec<RawDebit<'_>>],
    contexts: &mut [Option<Value>],
    meter: &mut AuditMeter,
) -> Result<AuditInventory, AuditFailure> {
    let last_site = last_site(rows);
    let expected = prospective_counts(rows, parents, children, debits, contexts, meter)?;
    meter.can_retain(expected.bytes, expected.items, last_site)?;
    let mut generations = Vec::new();
    meter.reserve(&mut generations, rows.generations.len(), last_site)?;
    for generation in &rows.generations {
        let site = generation_location(generation, "pn_admission_generations", None);
        let mut versions = Vec::new();
        meter.reserve(&mut versions, generation.versions.len(), site)?;
        for row in &generation.versions {
            let row_site = version_location(row.family, &row.key, &row.edition, "pn_versions");
            versions.push(version(row, meter, row_site)?);
        }
        let mut closures = Vec::new();
        meter.reserve(&mut closures, generation.closures.len(), site)?;
        for closure in &generation.closures {
            let site = version_location(closure.family, &closure.key, &closure.edition, "pn_closures");
            closures.push(array(
                [
                    family(closure.family),
                    text(&closure.key, meter, site)?,
                    text(&closure.edition, meter, site)?,
                    Value::Unsigned(closure.closes_at),
                ],
                meter,
                site,
            )?);
        }
        let entry = array(
            [
                text(&generation.key, meter, site)?,
                Value::Unsigned(generation.declaration.ordinal),
                Value::Null,
                Value::Unsigned(generation.declaration.minimum),
                text(&generation.declaration.label, meter, site)?,
                sequence(&mut versions),
                sequence(&mut closures),
            ],
            meter,
            site,
        )?;
        retain_entry(&mut generations, entry, meter, site)?;
    }

    let mut histories = Vec::new();
    let history_capacity = rows
        .generations
        .iter()
        .map(|generation| generation.versions.len())
        .chain(rows.results.iter().map(|row| row.content().observations.len()))
        .try_fold(0usize, |total, count| total.checked_add(count).ok_or_else(count_overflow))?;
    meter.reserve(&mut histories, history_capacity, last_site)?;
    let mut history_rows = Vec::new();
    meter.reserve(&mut history_rows, history_capacity, last_site)?;
    for generation in &rows.generations {
        for version in &generation.versions {
            meter.visit(generation_location(generation, "pn_admission_generations", None))?;
            let close = generation
                .closures
                .binary_search_by(|closure| {
                    (closure.family.name(), closure.key.as_str(), closure.edition.as_str()).cmp(&(
                        version.family.name(),
                        version.key.as_str(),
                        version.edition.as_str(),
                    ))
                })
                .ok()
                .map(|at| generation.closures[at].closes_at);
            history_rows.push((*version, generation.key.as_str(), generation.declaration.ordinal, close));
        }
    }
    for row in &rows.results {
        for observed in &row.content().observations {
            history_rows.push((*observed, row.key.as_str(), row.generation, None));
        }
    }
    history_rows.sort_unstable_by(|a, b| {
        (a.0.family.name(), &a.0.key, &a.0.edition, a.1).cmp(&(b.0.family.name(), &b.0.key, &b.0.edition, b.1))
    });
    for (version_row, key, ordinal, close) in history_rows {
        let site = version_location(version_row.family, &version_row.key, &version_row.edition, "pn_versions");
        let interval = array(
            [
                text(key, meter, site)?,
                Value::Unsigned(ordinal),
                Value::Unsigned(version_row.opens_at),
                close.map_or(Value::Null, Value::Unsigned),
            ],
            meter,
            site,
        )?;
        let mut intervals = Vec::new();
        meter.reserve(&mut intervals, 1, site)?;
        intervals.push(interval);
        let entry = array([version(version_row, meter, site)?, sequence(&mut intervals)], meter, site)?;
        retain_entry(&mut histories, entry, meter, site)?;
    }

    let mut scopes = Vec::new();
    meter.reserve(&mut scopes, rows.scopes.len(), last_site)?;
    for (scope_at, scope) in rows.scopes.iter().enumerate() {
        let site = scope_location(scope.scope);
        let mut roots = Vec::new();
        let mut tips = Vec::new();
        meter.visit(scope_location(scope.scope))?;
        let first = rows.results.partition_point(|row| row.key < scope.key);
        meter.visit(scope_location(scope.scope))?;
        let last = rows.results.partition_point(|row| row.key <= scope.key);
        let count = last - first;
        meter.reserve(&mut roots, count, site)?;
        meter.reserve(&mut tips, count, site)?;
        for at in first..last {
            let row = &rows.results[at];
            meter.visit(result_location(row.scope, row.identity))?;
            if parents[at].is_none() {
                roots.push(bytes(&row.identity, meter, result_location(row.scope, row.identity))?);
            }
            if children[at].is_empty() {
                tips.push(bytes(&row.identity, meter, result_location(row.scope, row.identity))?);
            }
        }
        let context = contexts[scope_at]
            .take()
            .ok_or_else(|| meter.refused(crate::storage::StorageError::CorruptHistory, site))?;
        // The context projection already belongs to the position owner. Its owned
        // value is moved into the inventory after the complete comparison pass.
        let entry = array(
            [
                text(&scope.key, meter, site)?,
                context,
                sequence(&mut roots),
                sequence(&mut tips),
            ],
            meter,
            site,
        )?;
        retain_entry(&mut scopes, entry, meter, site)?;
    }

    let mut results = Vec::new();
    meter.reserve(&mut results, rows.results.len(), last_site)?;
    for (at, row) in rows.results.iter().enumerate() {
        let site = result_location(row.scope, row.identity);
        let mut selections = Vec::new();
        meter.reserve(&mut selections, row.content().selections.len(), site)?;
        let mut order = Vec::new();
        meter.reserve(&mut order, row.content().selections.len(), site)?;
        order.extend(0..row.content().selections.len());
        order.sort_unstable_by(|&a, &b| {
            let a = row.content().selections[a].use_.as_ref();
            let b = row.content().selections[b].use_.as_ref();
            (a.selected_at, a.version.family.name(), &a.version.key, &a.version.edition).cmp(&(
                b.selected_at,
                b.version.family.name(),
                &b.version.key,
                &b.version.edition,
            ))
        });
        for offset in order {
            let selection = &row.content().selections[offset];
            let site = reference_location(row.scope, row.identity, selection.use_.as_ref());
            selections.push(array(
                [
                    Value::Unsigned(selection.use_.selected_at),
                    version(&selection.use_.version, meter, site)?,
                    bytes(&selection.origin, meter, site)?,
                ],
                meter,
                site,
            )?);
        }
        let mut complete_debits = Vec::new();
        meter.reserve(&mut complete_debits, debits[at].len(), site)?;
        for debit in &debits[at] {
            let site = debit_location(debit.scope, debit.origin, debit.act, "pn_epoch_debits", None);
            let act = debit.act;
            complete_debits.push(array(
                [
                    array(
                        [
                            text(&act.author, meter, site)?,
                            Value::Unsigned(act.sequence),
                            text(&act.family, meter, site)?,
                        ],
                        meter,
                        site,
                    )?,
                    bytes(&debit.origin, meter, site)?,
                    bytes(debit.bytes, meter, site)?,
                ],
                meter,
                site,
            )?);
        }
        let parent = row.parent.map_or(Ok(Value::Null), |parent| bytes(&parent, meter, site))?;
        let entry = array(
            [
                text(&row.key, meter, site)?,
                bytes(&row.identity, meter, site)?,
                parent,
                Value::Unsigned(row.depth),
                bytes(row.content().package.as_ref(), meter, site)?,
                text(row.label, meter, site)?,
                Value::Unsigned(row.generation),
                sequence(&mut selections),
                sequence(&mut complete_debits),
            ],
            meter,
            site,
        )?;
        retain_entry(&mut results, entry, meter, site)?;
    }
    let generation_count = generations.len();
    let history_count = histories.len();
    let scope_count = scopes.len();
    let result_count = results.len();
    let site = last_site;
    let tree = array(
        [
            sequence(&mut generations),
            sequence(&mut histories),
            sequence(&mut scopes),
            sequence(&mut results),
        ],
        meter,
        site,
    )?;
    let (logical_bytes, logical_items) = counts(&tree)?;
    if (logical_bytes, logical_items) != (expected.bytes, expected.items) {
        return Err(meter.refused(crate::storage::StorageError::CorruptHistory, site));
    }
    meter.retain(0, 5, site)?;
    Ok(AuditInventory {
        tree,
        generations: generation_count,
        histories: history_count,
        scopes: scope_count,
        results: result_count,
        logical_bytes,
        logical_items,
    })
}
