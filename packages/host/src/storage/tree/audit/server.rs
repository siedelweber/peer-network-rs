//! Independent bounded server scans for one complete audit snapshot.
//! (´[ROOT-amend:storage:tree-audit]´)

use super::{AuditFailure, AuditMeter, AuditSite, SitePart};
use super::{
    AuditInventory, AuditSource, Collected, RawContent, RawDescriptor, RawGeneration, RawObservation, RawResult, RawScope,
};
use crate::admitted_result::EpochScope;
use crate::storage::tree::{Closure, Generation, Identity};
use crate::storage::{Family, Payload, Version};
use crate::storage::{Statement, StatementParameter, StatementRow, StatementTransaction, StorageError, observed};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
enum Field {
    Text { bound: usize, nullable: bool },
    Bytes { bound: usize, nullable: bool },
    Integer { minimum: i64, nullable: bool },
}

const fn text(bound: usize) -> Field {
    Field::Text { bound, nullable: false }
}
const fn bytes(bound: usize) -> Field {
    Field::Bytes { bound, nullable: false }
}
const fn optional_bytes(bound: usize) -> Field {
    Field::Bytes { bound, nullable: true }
}
const fn integer(minimum: i64) -> Field {
    Field::Integer {
        minimum,
        nullable: false,
    }
}
const fn optional_integer(minimum: i64) -> Field {
    Field::Integer { minimum, nullable: true }
}

#[derive(Clone, Copy)]
enum Scan {
    Page {
        statement: Statement,
        multiplicity: Statement,
    },
    Cursor {
        open: Statement,
        one: Statement,
        sixty_four: Statement,
        close: Statement,
    },
}

struct Spec {
    relation: &'static str,
    fields: &'static [Field],
    key: &'static [usize],
    maximum: usize,
    scan: Scan,
}

const SPECS: &[Spec] = &[
    Spec {
        relation: "pn_admission_generations",
        fields: &[
            text(1024),
            integer(1),
            text(1024),
            optional_integer(1),
            integer(1),
            integer(0),
            integer(0),
        ],
        key: &[0, 1],
        maximum: 2142,
        scan: Scan::Page {
            statement: Statement::AuditAdmissionGenerations,
            multiplicity: Statement::AuditKeyMultiplicityAdmissionGenerations,
        },
    },
    Spec {
        relation: "pn_admission_versions",
        fields: &[text(1024), integer(1), text(21), text(1024), text(1024)],
        key: &[2, 3, 4],
        maximum: 3171,
        scan: Scan::Page {
            statement: Statement::AuditAdmissionVersions,
            multiplicity: Statement::AuditKeyMultiplicityAdmissionVersions,
        },
    },
    Spec {
        relation: "pn_admission_closures",
        fields: &[text(1024), integer(1), text(21), text(1024), text(1024)],
        key: &[2, 3, 4],
        maximum: 3171,
        scan: Scan::Page {
            statement: Statement::AuditAdmissionClosures,
            multiplicity: Statement::AuditKeyMultiplicityAdmissionClosures,
        },
    },
    Spec {
        relation: "pn_epoch_scopes",
        fields: &[text(1024), bytes(32)],
        key: &[0],
        maximum: 1090,
        scan: Scan::Page {
            statement: Statement::AuditScopes,
            multiplicity: Statement::AuditKeyMultiplicityScopes,
        },
    },
    Spec {
        relation: "pn_epoch_results",
        fields: &[
            text(1024),
            bytes(32),
            integer(1),
            optional_bytes(32),
            optional_integer(1),
            optional_bytes(32),
            bytes(32),
            integer(1),
            integer(1),
            integer(1),
            integer(0),
            integer(0),
        ],
        key: &[0, 1],
        maximum: 1318,
        scan: Scan::Page {
            statement: Statement::AuditResults,
            multiplicity: Statement::AuditKeyMultiplicityResults,
        },
    },
    Spec {
        relation: "pn_epoch_branches",
        fields: &[
            text(1024),
            bytes(32),
            integer(1),
            optional_bytes(32),
            optional_bytes(32),
            integer(0),
        ],
        key: &[0, 1],
        maximum: 1210,
        scan: Scan::Page {
            statement: Statement::AuditSegments,
            multiplicity: Statement::AuditKeyMultiplicitySegments,
        },
    },
    Spec {
        relation: "pn_versions",
        fields: &[
            text(21),
            text(1024),
            text(1024),
            integer(0),
            integer(0),
            optional_bytes(262_144),
            optional_bytes(32),
            optional_bytes(32),
        ],
        key: &[0, 1, 2],
        maximum: 264_399,
        scan: Scan::Cursor {
            open: Statement::AuditVersionsOpen,
            one: Statement::AuditVersionsFetchOne,
            sixty_four: Statement::AuditVersionsFetchSixtyFour,
            close: Statement::AuditVersionsClose,
        },
    },
    Spec {
        relation: "pn_closures",
        fields: &[text(21), text(1024), text(1024), integer(0)],
        key: &[0, 1, 2],
        maximum: 2131,
        scan: Scan::Cursor {
            open: Statement::AuditClosuresOpen,
            one: Statement::AuditClosuresFetchOne,
            sixty_four: Statement::AuditClosuresFetchSixtyFour,
            close: Statement::AuditClosuresClose,
        },
    },
    Spec {
        relation: "pn_epoch_package_chunks",
        fields: &[text(1024), bytes(32), integer(0), bytes(262_144)],
        key: &[0, 1, 2],
        maximum: 263_262,
        scan: Scan::Page {
            statement: Statement::AuditResultChunks,
            multiplicity: Statement::AuditKeyMultiplicityResultChunks,
        },
    },
    Spec {
        relation: "pn_epoch_references",
        fields: &[text(1024), bytes(32), integer(0), text(21), text(1024), text(1024), bytes(32)],
        key: &[0, 1, 2, 3, 4],
        maximum: 3267,
        scan: Scan::Page {
            statement: Statement::AuditReferences,
            multiplicity: Statement::AuditKeyMultiplicityReferences,
        },
    },
    Spec {
        relation: "pn_epoch_debits",
        fields: &[
            text(1024),
            bytes(32),
            text(1024),
            text(20),
            text(1024),
            integer(1),
            integer(1),
            integer(1),
        ],
        key: &[0, 1, 2, 3, 4],
        maximum: 1168,
        scan: Scan::Page {
            statement: Statement::AuditDebits,
            multiplicity: Statement::AuditKeyMultiplicityDebits,
        },
    },
    Spec {
        relation: "pn_epoch_debit_chunks",
        fields: &[
            text(1024),
            bytes(32),
            text(1024),
            text(20),
            text(1024),
            integer(0),
            bytes(262_144),
        ],
        key: &[0, 1, 2, 3, 4, 5],
        maximum: 263_304,
        scan: Scan::Page {
            statement: Statement::AuditDebitChunks,
            multiplicity: Statement::AuditKeyMultiplicityDebitChunks,
        },
    },
    Spec {
        relation: "pn_epoch_result_debits",
        fields: &[text(1024), bytes(32), text(1024), text(20), text(1024), bytes(32), integer(1)],
        key: &[0, 1, 2, 3, 4],
        maximum: 1192,
        scan: Scan::Page {
            statement: Statement::AuditIntroductions,
            multiplicity: Statement::AuditKeyMultiplicityIntroductions,
        },
    },
];

enum Cell {
    Text(String),
    Bytes(Vec<u8>),
    Integer(i64),
    Null,
}

struct RawRow {
    cells: Vec<Cell>,
}

impl RawRow {
    fn text(&self, field: usize) -> Option<&str> {
        match self.cells.get(field)? {
            Cell::Text(value) => Some(value),
            _ => None,
        }
    }

    fn bytes(&self, field: usize) -> Option<&[u8]> {
        match self.cells.get(field)? {
            Cell::Bytes(value) => Some(value),
            _ => None,
        }
    }

    fn integer(&self, field: usize) -> Option<i64> {
        match self.cells.get(field)? {
            Cell::Integer(value) => Some(*value),
            _ => None,
        }
    }

    fn site<'a>(&'a self, spec: &'static Spec) -> AuditSite<'a> {
        let mut parts = [SitePart::Empty; 6];
        for (slot, field) in spec.key.iter().copied().enumerate() {
            parts[slot] = match (&self.cells[field], spec.fields[field]) {
                (Cell::Text(value), Field::Text { bound: 1024, .. })
                    if field == 0 && spec.relation != "pn_versions" && spec.relation != "pn_closures" =>
                {
                    SitePart::ScopeText(value)
                }
                (Cell::Text(value), Field::Text { bound, .. }) => SitePart::Text(value, bound),
                (Cell::Bytes(value), Field::Bytes { bound, .. }) => SitePart::RawBytes(value, bound),
                (Cell::Integer(value), Field::Integer { .. }) => SitePart::Signed(*value),
                _ => return AuditSite::NotRead,
            };
        }
        AuditSite::row(spec.relation, &parts[..spec.key.len()])
    }
}

fn parse_decimal(value: &str) -> Option<usize> {
    if value.is_empty() || value.starts_with('+') || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

fn copy_text(value: &str, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<String, AuditFailure> {
    meter.copy_text(value, site)
}

fn scope_parts(value: &str) -> Option<[&str; 4]> {
    let (count, mut rest) = value.split_once(':')?;
    if parse_decimal(count) != Some(4) {
        return None;
    }
    let mut fields = [""; 4];
    for field in &mut fields {
        let (length, after_length) = rest.split_once(':')?;
        let length = parse_decimal(length)?;
        let (value, tail) = after_length.get(..length).zip(after_length.get(length..))?;
        if value.contains('\0') {
            return None;
        }
        *field = value;
        rest = tail;
    }
    if !rest.is_empty() {
        return None;
    }
    Some(fields)
}

fn parse_scope(value: &str, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<EpochScope, AuditFailure> {
    let fields = scope_parts(value).ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))?;
    Ok(EpochScope {
        history: copy_text(fields[0], site, meter)?,
        policy_identity: copy_text(fields[1], site, meter)?,
        policy_edition: copy_text(fields[2], site, meter)?,
        sequence: copy_text(fields[3], site, meter)?,
    })
}

struct Arena {
    domains: [Vec<RawRow>; 13],
}

fn identity_cell(row: &RawRow, field: usize, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<Identity, AuditFailure> {
    row.bytes(field)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))
}

fn optional_identity_cell(
    row: &RawRow,
    field: usize,
    site: AuditSite<'_>,
    meter: &mut AuditMeter,
) -> Result<Option<Identity>, AuditFailure> {
    match row.cells.get(field) {
        Some(Cell::Null) => Ok(None),
        Some(Cell::Bytes(value)) => value
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| meter.refused(StorageError::CorruptHistory, site)),
        _ => Err(meter.refused(StorageError::CorruptHistory, site)),
    }
}

fn unsigned_cell(row: &RawRow, field: usize, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<u64, AuditFailure> {
    row.integer(field)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))
}

fn text_cell<'a>(row: &'a RawRow, field: usize, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<&'a str, AuditFailure> {
    row.text(field)
        .ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))
}

fn copied_bytes(value: &[u8], site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<Vec<u8>, AuditFailure> {
    meter.copy_bytes(value, site)
}

fn family_cell(row: &RawRow, field: usize, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<Family, AuditFailure> {
    let value = text_cell(row, field, site, meter)?;
    crate::storage::tree::server::family(value).map_err(|_| meter.refused(StorageError::CorruptHistory, site))
}

fn version(row: &RawRow, meter: &mut AuditMeter) -> Result<Version, AuditFailure> {
    let site = row.site(&SPECS[6]);
    let family = family_cell(row, 0, site, meter)?;
    let key = copy_text(text_cell(row, 1, site, meter)?, site, meter)?;
    let edition = copy_text(text_cell(row, 2, site, meter)?, site, meter)?;
    let announced_at = unsigned_cell(row, 3, site, meter)?;
    let opens_at = unsigned_cell(row, 4, site, meter)?;
    let payload = match (&row.cells[5], &row.cells[6], &row.cells[7]) {
        (Cell::Null, Cell::Null, Cell::Null) => None,
        (Cell::Bytes(bytes), Cell::Bytes(digest), disclosure) => {
            let digest = digest
                .as_slice()
                .try_into()
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            let disclosure = match disclosure {
                Cell::Null => None,
                Cell::Bytes(bytes) => Some(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?,
                ),
                _ => return Err(meter.refused(StorageError::CorruptHistory, site)),
            };
            Some(Payload {
                family,
                bytes: copied_bytes(bytes, site, meter)?,
                digest,
                disclosure,
            })
        }
        _ => return Err(meter.refused(StorageError::CorruptHistory, site)),
    };
    Ok(Version {
        family,
        key,
        edition,
        announced_at,
        opens_at,
        payload,
    })
}

fn closure(row: &RawRow, meter: &mut AuditMeter) -> Result<Closure, AuditFailure> {
    let site = row.site(&SPECS[7]);
    Ok(Closure {
        family: family_cell(row, 0, site, meter)?,
        key: copy_text(text_cell(row, 1, site, meter)?, site, meter)?,
        edition: copy_text(text_cell(row, 2, site, meter)?, site, meter)?,
        closes_at: unsigned_cell(row, 3, site, meter)?,
    })
}

fn clone_version(value: &Version, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<Version, AuditFailure> {
    let payload = value
        .payload
        .as_ref()
        .map(|payload| {
            Ok(Payload {
                family: payload.family,
                bytes: copied_bytes(&payload.bytes, site, meter)?,
                digest: payload.digest,
                disclosure: payload.disclosure,
            })
        })
        .transpose()?;
    Ok(Version {
        family: value.family,
        key: copy_text(&value.key, site, meter)?,
        edition: copy_text(&value.edition, site, meter)?,
        announced_at: value.announced_at,
        opens_at: value.opens_at,
        payload,
    })
}

fn clone_closure(value: &Closure, site: AuditSite<'_>, meter: &mut AuditMeter) -> Result<Closure, AuditFailure> {
    Ok(Closure {
        family: value.family,
        key: copy_text(&value.key, site, meter)?,
        edition: copy_text(&value.edition, site, meter)?,
        closes_at: value.closes_at,
    })
}

impl Arena {
    fn empty() -> Self {
        Self {
            domains: std::array::from_fn(|_| Vec::new()),
        }
    }
}

fn column_at(spec: &Spec, field: usize) -> usize {
    spec.fields[..field]
        .iter()
        .map(|kind| if matches!(kind, Field::Integer { .. }) { 1 } else { 2 })
        .sum()
}

fn projected_site<'a>(row: &'a StatementRow, spec: &'static Spec) -> AuditSite<'a> {
    let mut parts = [SitePart::Empty; 6];
    for (slot, field) in spec.key.iter().copied().enumerate() {
        let at = column_at(spec, field);
        parts[slot] = match spec.fields[field] {
            Field::Text { bound, .. } => {
                let (Ok(Some(value)), Ok(Some(length))) =
                    (row.try_get::<_, Option<&str>>(at), row.try_get::<_, Option<i64>>(at + 1))
                else {
                    return AuditSite::NotRead;
                };
                if length < 0 || usize::try_from(length).ok().is_none_or(|length| length > bound) {
                    return AuditSite::OverBound;
                }
                if field == 0 && spec.relation != "pn_versions" && spec.relation != "pn_closures" {
                    SitePart::ScopeText(value)
                } else {
                    SitePart::Text(value, bound)
                }
            }
            Field::Bytes { bound, .. } => {
                let (Ok(Some(value)), Ok(Some(length))) =
                    (row.try_get::<_, Option<&[u8]>>(at), row.try_get::<_, Option<i64>>(at + 1))
                else {
                    return AuditSite::NotRead;
                };
                if length < 0 || usize::try_from(length).ok().is_none_or(|length| length > bound) {
                    return AuditSite::OverBound;
                }
                SitePart::RawBytes(value, bound)
            }
            Field::Integer { .. } => match row.try_get::<_, Option<i64>>(at) {
                Ok(Some(value)) => SitePart::Signed(value),
                _ => return AuditSite::NotRead,
            },
        };
    }
    AuditSite::row(spec.relation, &parts[..spec.key.len()])
}

fn inspect_joint_debit(
    row: &StatementRow,
    spec: &'static Spec,
    meter: &mut AuditMeter,
    site: AuditSite<'_>,
) -> Result<(), AuditFailure> {
    if matches!(
        spec.relation,
        "pn_epoch_debits" | "pn_epoch_debit_chunks" | "pn_epoch_result_debits"
    ) {
        let lengths = [0, 2, 3, 4].map(|field| {
            let at = column_at(spec, field);
            row.try_get::<_, Option<i64>>(at + 1)
                .ok()
                .flatten()
                .and_then(|length| usize::try_from(length).ok())
        });
        let [Some(scope), Some(author), Some(sequence), Some(family)] = lengths else {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        };
        let digits = |value: usize| value.max(1).ilog10() as usize + 1;
        let joint = scope
            .checked_add(author)
            .and_then(|total| total.checked_add(sequence))
            .and_then(|total| total.checked_add(family))
            .and_then(|total| total.checked_add(digits(author) + digits(sequence) + digits(family) + 3));
        if sequence > 20 || joint.is_none_or(|joint| joint > 1024) {
            return Err(meter.refused(StorageError::CorruptHistory, AuditSite::OverBound));
        }
    }
    Ok(())
}

fn inspect_row(row: &StatementRow, spec: &'static Spec, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
    let site = projected_site(row, spec);
    let expected = column_at(spec, spec.fields.len());
    if row.len() != expected {
        return Err(meter.refused(StorageError::CorruptHistory, site));
    }
    inspect_joint_debit(row, spec, meter, site)?;
    for (field, kind) in spec.fields.iter().copied().enumerate() {
        let at = column_at(spec, field);
        match kind {
            Field::Text { bound, nullable } => {
                let value = row
                    .try_get::<_, Option<&str>>(at)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
                let length = row
                    .try_get::<_, Option<i64>>(at + 1)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
                if value.is_none() != length.is_none() || (!nullable && value.is_none()) {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
                if let Some(length) = length {
                    if length < 0 || usize::try_from(length).ok().is_none_or(|length| length > bound) {
                        let location = if spec.key.contains(&field) {
                            AuditSite::OverBound
                        } else {
                            site
                        };
                        return Err(meter.refused(StorageError::CorruptHistory, location));
                    }
                    if value.is_none_or(|text| text.len() != usize::try_from(length).unwrap_or(usize::MAX)) {
                        return Err(meter.refused(StorageError::CorruptHistory, site));
                    }
                    if let Some(value) = value {
                        let is_scope = field == 0 && spec.relation != "pn_versions" && spec.relation != "pn_closures";
                        let is_family = (spec.relation == "pn_versions" || spec.relation == "pn_closures") && field == 0
                            || matches!(spec.relation, "pn_admission_versions" | "pn_admission_closures") && field == 2
                            || spec.relation == "pn_epoch_references" && field == 3;
                        let is_sequence = matches!(
                            spec.relation,
                            "pn_epoch_debits" | "pn_epoch_debit_chunks" | "pn_epoch_result_debits"
                        ) && field == 3;
                        if is_scope && scope_parts(value).is_none()
                            || is_family
                                && !matches!(
                                    value,
                                    "rule"
                                        | "constants"
                                        | "marker-policy"
                                        | "lineage"
                                        | "burn-publication"
                                        | "unsettled-recognition"
                                )
                            || is_sequence && (parse_decimal(value).is_none() || value.parse::<u64>().is_err())
                        {
                            return Err(meter.refused(StorageError::CorruptHistory, site));
                        }
                    }
                }
            }
            Field::Bytes { bound, nullable } => {
                let value = row
                    .try_get::<_, Option<&[u8]>>(at)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
                let length = row
                    .try_get::<_, Option<i64>>(at + 1)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
                if value.is_none() != length.is_none() || (!nullable && value.is_none()) {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
                if let Some(length) = length {
                    if length < 0 || usize::try_from(length).ok().is_none_or(|length| length > bound) {
                        let location = if spec.key.contains(&field) {
                            AuditSite::OverBound
                        } else {
                            site
                        };
                        return Err(meter.refused(StorageError::CorruptHistory, location));
                    }
                    if value.is_none_or(|bytes| bytes.len() != usize::try_from(length).unwrap_or(usize::MAX)) {
                        return Err(meter.refused(StorageError::CorruptHistory, site));
                    }
                    if bound == 32 && length != 32 {
                        return Err(meter.refused(StorageError::CorruptHistory, site));
                    }
                }
            }
            Field::Integer { minimum, nullable } => {
                let value = row
                    .try_get::<_, Option<i64>>(at)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
                if value.is_none() && !nullable || value.is_some_and(|value| value < minimum) {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
    }
    Ok(())
}

fn copy_row(row: &StatementRow, spec: &'static Spec, meter: &mut AuditMeter) -> Result<RawRow, AuditFailure> {
    inspect_row(row, spec, meter)?;
    let site = projected_site(row, spec);
    let mut cells = Vec::new();
    meter.reserve(&mut cells, spec.fields.len(), site)?;
    for (field, kind) in spec.fields.iter().copied().enumerate() {
        let at = column_at(spec, field);
        let cell = match kind {
            Field::Text { .. } => match row.try_get::<_, Option<&str>>(at) {
                Ok(Some(value)) => {
                    meter.allocation(value.len(), site)?;
                    let mut copy = String::new();
                    copy.try_reserve_exact(value.len()).map_err(|_| meter.allocated(site))?;
                    copy.push_str(value);
                    Cell::Text(copy)
                }
                _ => Cell::Null,
            },
            Field::Bytes { .. } => match row.try_get::<_, Option<&[u8]>>(at) {
                Ok(Some(value)) => {
                    meter.allocation(value.len(), site)?;
                    let mut copy = Vec::new();
                    copy.try_reserve_exact(value.len()).map_err(|_| meter.allocated(site))?;
                    copy.extend_from_slice(value);
                    Cell::Bytes(copy)
                }
                _ => Cell::Null,
            },
            Field::Integer { .. } => row
                .try_get::<_, Option<i64>>(at)
                .ok()
                .flatten()
                .map_or(Cell::Null, Cell::Integer),
        };
        cells.push(cell);
    }
    Ok(RawRow { cells })
}

fn key_order(a: &RawRow, b: &RawRow, spec: &Spec) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for field in spec.key {
        let ordering = match (&a.cells[*field], &b.cells[*field]) {
            (Cell::Text(a), Cell::Text(b)) => a.cmp(b),
            (Cell::Bytes(a), Cell::Bytes(b)) => a.cmp(b),
            (Cell::Integer(a), Cell::Integer(b)) => a.cmp(b),
            _ => Ordering::Equal,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

async fn identity(transaction: &StatementTransaction<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
    meter.visit(AuditSite::NotRead)?;
    meter.allocation(58, AuditSite::NotRead)?;
    let rows = observed(transaction.query(Statement::AuditStoreIdentity, &[]))
        .await
        .map_err(|error| meter.refused(error, AuditSite::NotRead))?;
    if rows.len() != 1
        || rows[0].len() != 3
        || rows[0].try_get::<_, i64>(0).ok() != Some(1)
        || rows[0].try_get::<_, Option<&str>>(1).ok().flatten() != Some("pn-host/effective-history/v2")
        || rows[0].try_get::<_, Option<i64>>(2).ok().flatten() != Some(28)
    {
        return Err(meter.refused(StorageError::CorruptHistory, AuditSite::NotRead));
    }
    Ok(())
}

fn key_parameter(cell: &Cell) -> Option<StatementParameter<'_>> {
    match cell {
        Cell::Text(value) => Some(value),
        Cell::Bytes(value) => Some(value),
        Cell::Integer(value) => Some(value),
        Cell::Null => None,
    }
}

async fn multiplicity(
    transaction: &StatementTransaction<'_>,
    meter: &mut AuditMeter,
    spec: &'static Spec,
    statement: Statement,
    last: &RawRow,
) -> Result<(), AuditFailure> {
    let site = last.site(spec);
    meter.visit(site)?;
    meter.allocation(14, site)?;
    let dummy = 0i64;
    let mut params: [StatementParameter<'_>; 6] = [&dummy; 6];
    for (at, field) in spec.key.iter().copied().enumerate() {
        params[at] = key_parameter(&last.cells[field]).ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))?;
    }
    let rows = observed(transaction.query(statement, &params[..spec.key.len()]))
        .await
        .map_err(|error| meter.refused(error, site))?;
    if rows.len() != 1 || rows[0].len() != 1 || rows[0].try_get::<_, i64>(0).ok() != Some(1) {
        return Err(meter.refused(StorageError::CorruptHistory, site));
    }
    Ok(())
}

async fn keyset(
    transaction: &StatementTransaction<'_>,
    meter: &mut AuditMeter,
    spec: &'static Spec,
    page_rows: usize,
    statement: Statement,
    count_statement: Statement,
    out: &mut Vec<RawRow>,
) -> Result<(), AuditFailure> {
    loop {
        let site = out.last().map_or(AuditSite::NotRead, |row| row.site(spec));
        meter.visit(site)?;
        let chosen = page_rows.min(meter.remaining_rows());
        if chosen == 0 {
            return Err(meter.refused(StorageError::ReadLimit, site));
        }
        let ceiling = i64::try_from(chosen).map_err(|_| meter.refused(StorageError::ReadLimit, site))?;
        meter.admit_delivery(chosen, spec.maximum, site)?;
        let first = out.is_empty();
        let dummy_int = 0i64;
        let dummy_text: &str = "";
        let dummy_bytes: &[u8] = &[];
        let mut params: [StatementParameter<'_>; 8] = [&dummy_int; 8];
        params[0] = &first;
        for (at, field) in spec.key.iter().copied().enumerate() {
            params[at + 1] = if let Some(last) = out.last() {
                key_parameter(&last.cells[field]).ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))?
            } else {
                match spec.fields[field] {
                    Field::Text { .. } => &dummy_text,
                    Field::Bytes { .. } => &dummy_bytes,
                    Field::Integer { .. } => &dummy_int,
                }
            };
        }
        params[spec.key.len() + 1] = &ceiling;
        let rows = observed(transaction.query(statement, &params[..spec.key.len() + 2]))
            .await
            .map_err(|error| meter.refused(error, site))?;
        if rows.len() > chosen {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        meter.release_delivery(chosen - rows.len(), spec.maximum);
        let empty = rows.is_empty();
        for row in &rows {
            let next = copy_row(row, spec, meter)?;
            let site = next.site(spec);
            if out
                .last()
                .is_some_and(|prior| key_order(prior, &next, spec) != std::cmp::Ordering::Less)
            {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            meter.reserve(out, 1, site)?;
            out.push(next);
        }
        if empty {
            break;
        }
        multiplicity(
            transaction,
            meter,
            spec,
            count_statement,
            out.last().expect("nonempty page has a last key"),
        )
        .await?;
    }
    Ok(())
}

async fn cursor(
    transaction: &StatementTransaction<'_>,
    meter: &mut AuditMeter,
    spec: &'static Spec,
    page_rows: usize,
    scan: Scan,
    out: &mut Vec<RawRow>,
) -> Result<(), AuditFailure> {
    let Scan::Cursor {
        open,
        one,
        sixty_four,
        close,
    } = scan
    else {
        unreachable!("cursor is only called for a cursor scan")
    };
    observed(transaction.batch_execute(open))
        .await
        .map_err(|error| meter.refused(error, AuditSite::NotRead))?;
    loop {
        let site = out.last().map_or(AuditSite::NotRead, |row| row.site(spec));
        meter.visit(site)?;
        let available = page_rows.min(meter.remaining_rows());
        let (statement, chosen) = if available >= 64 {
            (sixty_four, 64)
        } else if available >= 1 {
            (one, 1)
        } else {
            return Err(meter.refused(StorageError::ReadLimit, site));
        };
        meter.admit_delivery(chosen, spec.maximum, site)?;
        #[cfg(test)]
        crate::storage::tree::server::tests::fetched();
        let rows = observed(transaction.query(statement, &[]))
            .await
            .map_err(|error| meter.refused(error, site))?;
        if rows.len() > chosen {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        meter.release_delivery(chosen - rows.len(), spec.maximum);
        let empty = rows.is_empty();
        for row in &rows {
            let next = copy_row(row, spec, meter)?;
            let site = next.site(spec);
            if out
                .last()
                .is_some_and(|prior| key_order(prior, &next, spec) != std::cmp::Ordering::Less)
            {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            meter.reserve(out, 1, site)?;
            out.push(next);
        }
        if empty {
            break;
        }
    }
    observed(transaction.batch_execute(close))
        .await
        .map_err(|error| meter.refused(error, out.last().map_or(AuditSite::NotRead, |row| row.site(spec))))?;
    Ok(())
}

async fn scan(transaction: &StatementTransaction<'_>, meter: &mut AuditMeter, page_rows: usize) -> Result<Arena, AuditFailure> {
    identity(transaction, meter).await?;
    let mut arena = Arena::empty();
    for (at, spec) in SPECS.iter().enumerate() {
        match spec.scan {
            Scan::Page { statement, multiplicity } => {
                keyset(
                    transaction,
                    meter,
                    spec,
                    page_rows,
                    statement,
                    multiplicity,
                    &mut arena.domains[at],
                )
                .await?;
            }
            Scan::Cursor { .. } => {
                cursor(transaction, meter, spec, page_rows, spec.scan, &mut arena.domains[at]).await?;
            }
        }
    }
    Ok(arena)
}

struct OwnedGeneration {
    key: String,
    declaration: Generation,
    version_order: Vec<usize>,
    closure_order: Vec<usize>,
}

struct OwnedScope {
    key: String,
    scope: EpochScope,
    pointer: Identity,
}

struct OwnedResult {
    key: String,
    scope: EpochScope,
    identity: Identity,
    parent: Option<Identity>,
    depth: u64,
    segment: Identity,
    generation: u64,
}

struct OwnedDescriptor {
    key: String,
    scope: EpochScope,
    segment: Identity,
    start: u64,
    parent_segment: Option<Identity>,
    fork: Option<Identity>,
    cutoff: u64,
}

struct OwnedVintage {
    act: pn_records::ActId,
    bytes: std::cell::OnceCell<Vec<u8>>,
}

struct ServerSource {
    arena: Arena,
    histories: Vec<Version>,
    generations: Vec<OwnedGeneration>,
    scopes: Vec<OwnedScope>,
    results: Vec<OwnedResult>,
    descriptors: Vec<OwnedDescriptor>,
    vintages: Vec<OwnedVintage>,
}

fn mapping_order(a: &RawRow, b: &RawRow) -> std::cmp::Ordering {
    (a.text(0), a.integer(1), a.text(2), a.text(3), a.text(4)).cmp(&(b.text(0), b.integer(1), b.text(2), b.text(3), b.text(4)))
}

fn mapping_index(domain: &[RawRow], meter: &mut AuditMeter, spec: &'static Spec) -> Result<Vec<usize>, AuditFailure> {
    let mut index = Vec::new();
    meter.reserve(&mut index, domain.len(), AuditSite::NotRead)?;
    for (at, row) in domain.iter().enumerate() {
        meter.visit(row.site(spec))?;
        index.push(at);
    }
    index.sort_unstable_by(|a, b| mapping_order(&domain[*a], &domain[*b]));
    Ok(index)
}

impl ServerSource {
    fn group<'a>(&'a self, at: usize, row: &RawResult<'_>, meter: &mut AuditMeter) -> Result<&'a [RawRow], AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        let domain = &self.arena.domains[at];
        let key = (Some(row.key.as_str()), Some(row.identity.as_slice()));
        meter.visit(site)?;
        let first = domain.partition_point(|candidate| (candidate.text(0), candidate.bytes(1)) < key);
        meter.visit(site)?;
        let last = domain.partition_point(|candidate| (candidate.text(0), candidate.bytes(1)) <= key);
        Ok(&domain[first..last])
    }

    fn header<'a>(&'a self, row: &RawResult<'_>, meter: &mut AuditMeter) -> Result<&'a RawRow, AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        meter.visit(site)?;
        self.arena.domains[4]
            .binary_search_by(|candidate| {
                (candidate.text(0), candidate.bytes(1)).cmp(&(Some(row.key.as_str()), Some(row.identity.as_slice())))
            })
            .ok()
            .map(|at| &self.arena.domains[4][at])
            .ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))
    }

    fn position(
        row: &RawResult<'_>,
        parent: Option<&RawResult<'_>>,
        meter: &mut AuditMeter,
    ) -> Result<pn_interchange::Value, AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        let child = crate::storage::tree::server::spans::Validated::audit(row.content().package.as_ref(), meter, site)?;
        let prior = parent
            .map(|parent| crate::storage::tree::server::spans::Validated::audit(parent.content().package.as_ref(), meter, site))
            .transpose()?;
        let mut usage = pn_interchange::EncodingUsage::default();
        let mut refusal = None;
        let ceiling = meter.remaining_allocation();
        let result = crate::admitted_result::position::from_stored_spans(
            &child,
            prior
                .as_ref()
                .zip(parent)
                .map(|(document, parent)| (document, &parent.identity)),
            ceiling,
            &mut usage,
            &mut |amount| match meter.allocation(amount, site) {
                Ok(_) => Ok(()),
                Err(error) => {
                    refusal = Some(error);
                    Err(())
                }
            },
        );
        if let Some(error) = refusal {
            return Err(error);
        }
        match result {
            Ok((residue, context, _bytes)) if residue == row.identity => Ok(context),
            Ok((_residue, _, _)) => Err(meter.refused(StorageError::CorruptHistory, site)),
            Err(crate::admitted_result::position::Error::Representation(
                crate::admitted_result::position::Representation::Encoding(pn_interchange::EncodingError::Allocation),
            )) => Err(meter.allocated(site)),
            Err(_) => Err(meter.refused(StorageError::CorruptHistory, site)),
        }
    }

    fn package(&self, row: &RawResult<'_>, header: &RawRow, meter: &mut AuditMeter) -> Result<Vec<u8>, AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        let group = self.group(8, row, meter)?;
        let expected_count = usize::try_from(unsigned_cell(header, 9, site, meter)?)
            .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
        let expected_bytes = usize::try_from(unsigned_cell(header, 8, site, meter)?)
            .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
        if group.len() != expected_count {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        let mut total = 0usize;
        for (at, chunk) in group.iter().enumerate() {
            let chunk_site = chunk.site(&SPECS[8]);
            meter.visit(chunk_site)?;
            if chunk.integer(2).and_then(|n| usize::try_from(n).ok()) != Some(at) {
                return Err(meter.refused(StorageError::CorruptHistory, chunk_site));
            }
            let bytes = chunk
                .bytes(3)
                .ok_or_else(|| meter.refused(StorageError::CorruptHistory, chunk_site))?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| meter.refused(StorageError::ReadLimit, chunk_site))?;
        }
        if total != expected_bytes {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        let mut output = Vec::new();
        meter.reserve(&mut output, total, site)?;
        for chunk in group {
            let chunk_site = chunk.site(&SPECS[8]);
            meter.visit(chunk_site)?;
            output.extend_from_slice(
                chunk
                    .bytes(3)
                    .ok_or_else(|| meter.refused(StorageError::CorruptHistory, chunk_site))?,
            );
        }
        Ok(output)
    }

    fn selections<'a>(
        &'a self,
        row: &RawResult<'a>,
        header: &RawRow,
        meter: &mut AuditMeter,
    ) -> Result<(Vec<super::RawSelection<'a>>, Vec<&'a Version>), AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        let group = self.group(9, row, meter)?;
        if unsigned_cell(header, 10, site, meter)? != u64::try_from(group.len()).unwrap_or(u64::MAX) {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        let mut selections = Vec::new();
        let mut observations = Vec::new();
        meter.reserve(&mut selections, group.len(), site)?;
        meter.reserve(&mut observations, group.len(), site)?;
        for reference in group {
            let ref_site = reference.site(&SPECS[9]);
            meter.visit(ref_site)?;
            let family = family_cell(reference, 3, ref_site, meter)?;
            let target = (Some(family.name()), reference.text(4), reference.text(5));
            meter.visit(ref_site)?;
            let found = self
                .histories
                .binary_search_by(|version| {
                    (
                        Some(version.family.name()),
                        Some(version.key.as_str()),
                        Some(version.edition.as_str()),
                    )
                        .cmp(&target)
                })
                .map_err(|_| meter.refused(StorageError::CorruptHistory, ref_site))?;
            let expected = &self.histories[found];
            let origin = identity_cell(reference, 6, ref_site, meter)?;
            let use_ = crate::admitted_result::DeclarationUse {
                selected_at: unsigned_cell(reference, 2, ref_site, meter)?,
                version: clone_version(expected, ref_site, meter)?,
            };
            if matches!(family, Family::Rule | Family::Constants) {
                meter.visit(ref_site)?;
                let origin_at = self
                    .results
                    .binary_search_by(|candidate| (candidate.key.as_str(), candidate.identity).cmp(&(&row.key, origin)))
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, ref_site))?;
                let source = &self.results[origin_at];
                meter.visit(ref_site)?;
                let generation_at = self
                    .generations
                    .binary_search_by(|candidate| candidate.key.cmp(&source.key))
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, ref_site))?;
                let generation = &self.generations[generation_at];
                match super::super::MemoryTree::selected_indexed(
                    &generation.declaration,
                    &generation.version_order,
                    &generation.closure_order,
                    &use_,
                    &mut meter.core,
                    true,
                ) {
                    Ok(()) => {}
                    Err(super::super::Error::Storage(StorageError::ReadLimit)) => {
                        return Err(meter.refused(StorageError::ReadLimit, ref_site));
                    }
                    Err(_) => return Err(meter.refused(StorageError::CorruptHistory, ref_site)),
                }
            } else {
                observations.push(expected);
            }
            selections.push(super::RawSelection {
                use_: std::borrow::Cow::Owned(use_),
                origin,
            });
        }
        Ok((selections, observations))
    }

    fn vintage_bytes<'a>(&'a self, at: usize, meter: &mut AuditMeter) -> Result<&'a [u8], AuditFailure> {
        let header = &self.arena.domains[10][at];
        let site = header.site(&SPECS[10]);
        let owned = &self.vintages[at];
        if owned.bytes.get().is_none() {
            let domain = &self.arena.domains[11];
            let key = (
                header.text(0),
                header.bytes(1),
                header.text(2),
                header.text(3),
                header.text(4),
            );
            meter.visit(site)?;
            let first = domain.partition_point(|row| (row.text(0), row.bytes(1), row.text(2), row.text(3), row.text(4)) < key);
            meter.visit(site)?;
            let last = domain.partition_point(|row| (row.text(0), row.bytes(1), row.text(2), row.text(3), row.text(4)) <= key);
            let chunks = &domain[first..last];
            let expected_count = usize::try_from(unsigned_cell(header, 7, site, meter)?)
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            let expected_bytes = usize::try_from(unsigned_cell(header, 6, site, meter)?)
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            if chunks.len() != expected_count {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            let mut total = 0usize;
            for (slot, chunk) in chunks.iter().enumerate() {
                let chunk_site = chunk.site(&SPECS[11]);
                meter.visit(chunk_site)?;
                if chunk.integer(5).and_then(|value| usize::try_from(value).ok()) != Some(slot) {
                    return Err(meter.refused(StorageError::CorruptHistory, chunk_site));
                }
                let bytes = chunk
                    .bytes(6)
                    .ok_or_else(|| meter.refused(StorageError::CorruptHistory, chunk_site))?;
                total = total
                    .checked_add(bytes.len())
                    .ok_or_else(|| meter.refused(StorageError::ReadLimit, chunk_site))?;
            }
            if total != expected_bytes {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            let mut output = Vec::new();
            meter.reserve(&mut output, total, site)?;
            for chunk in chunks {
                let chunk_site = chunk.site(&SPECS[11]);
                meter.visit(chunk_site)?;
                output.extend_from_slice(
                    chunk
                        .bytes(6)
                        .ok_or_else(|| meter.refused(StorageError::CorruptHistory, chunk_site))?,
                );
            }
            drop(crate::storage::tree::server::spans::Validated::audit(&output, meter, site)?);
            owned
                .bytes
                .set(output)
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
        }
        Ok(owned.bytes.get().expect("vintage assembled before borrow"))
    }

    fn local<'a>(
        &'a self,
        row: &RawResult<'a>,
        header: &RawRow,
        meter: &mut AuditMeter,
    ) -> Result<Vec<super::RawDebit<'a>>, AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        let group = self.group(12, row, meter)?;
        if u64::try_from(group.len()).unwrap_or(u64::MAX) > unsigned_cell(header, 11, site, meter)? {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        let mut local = Vec::new();
        meter.reserve(&mut local, group.len(), site)?;
        for introduction in group {
            let introduction_site = introduction.site(&SPECS[12]);
            meter.visit(introduction_site)?;
            let target = (
                introduction.text(0),
                introduction.bytes(1),
                introduction.text(2),
                introduction.text(3),
                introduction.text(4),
            );
            meter.visit(introduction_site)?;
            let at = self.arena.domains[10]
                .binary_search_by(|header| {
                    (
                        header.text(0),
                        header.bytes(1),
                        header.text(2),
                        header.text(3),
                        header.text(4),
                    )
                        .cmp(&target)
                })
                .map_err(|_| meter.refused(StorageError::CorruptHistory, introduction_site))?;
            let bytes = self.vintage_bytes(at, meter)?;
            local.push(super::RawDebit {
                scope: row.scope,
                origin: row.identity,
                act: &self.vintages[at].act,
                bytes,
            });
        }
        Ok(local)
    }

    // Justified: Normalization retains all scanned domains; logical joins remain in the common phase.
    #[allow(clippy::too_many_lines)]
    fn new(arena: Arena, meter: &mut AuditMeter) -> Result<Self, AuditFailure> {
        let mut histories = Vec::new();
        meter.reserve(&mut histories, arena.domains[6].len(), AuditSite::NotRead)?;
        for row in &arena.domains[6] {
            let site = row.site(&SPECS[6]);
            meter.visit(site)?;
            histories.push(version(row, meter)?);
        }
        let mut closures = Vec::new();
        meter.reserve(&mut closures, arena.domains[7].len(), AuditSite::NotRead)?;
        for row in &arena.domains[7] {
            let site = row.site(&SPECS[7]);
            meter.visit(site)?;
            closures.push(closure(row, meter)?);
        }
        let versions_index = mapping_index(&arena.domains[1], meter, &SPECS[1])?;
        let closures_index = mapping_index(&arena.domains[2], meter, &SPECS[2])?;
        let mut generations = Vec::new();
        meter.reserve(&mut generations, arena.domains[0].len(), AuditSite::NotRead)?;
        for row in &arena.domains[0] {
            let site = row.site(&SPECS[0]);
            meter.visit(site)?;
            let key = text_cell(row, 0, site, meter)?;
            let ordinal = unsigned_cell(row, 1, site, meter)?;
            let mut versions = Vec::new();
            let mut declared_closures = Vec::new();
            let target = (Some(key), row.integer(1));
            meter.visit(site)?;
            let version_first =
                versions_index.partition_point(|&at| (arena.domains[1][at].text(0), arena.domains[1][at].integer(1)) < target);
            meter.visit(site)?;
            let version_last =
                versions_index.partition_point(|&at| (arena.domains[1][at].text(0), arena.domains[1][at].integer(1)) <= target);
            meter.reserve(&mut versions, version_last - version_first, site)?;
            for &at in &versions_index[version_first..version_last] {
                let mapping = &arena.domains[1][at];
                let mapping_site = mapping.site(&SPECS[1]);
                meter.visit(mapping_site)?;
                let target = (mapping.text(2), mapping.text(3), mapping.text(4));
                meter.visit(mapping_site)?;
                let found = histories.binary_search_by(|history| {
                    (
                        Some(history.family.name()),
                        Some(history.key.as_str()),
                        Some(history.edition.as_str()),
                    )
                        .cmp(&target)
                });
                if let Ok(found) = found {
                    versions.push(clone_version(&histories[found], mapping_site, meter)?);
                }
            }
            meter.visit(site)?;
            let closure_first =
                closures_index.partition_point(|&at| (arena.domains[2][at].text(0), arena.domains[2][at].integer(1)) < target);
            meter.visit(site)?;
            let closure_last =
                closures_index.partition_point(|&at| (arena.domains[2][at].text(0), arena.domains[2][at].integer(1)) <= target);
            meter.reserve(&mut declared_closures, closure_last - closure_first, site)?;
            for &at in &closures_index[closure_first..closure_last] {
                let mapping = &arena.domains[2][at];
                let mapping_site = mapping.site(&SPECS[2]);
                meter.visit(mapping_site)?;
                let target = (mapping.text(2), mapping.text(3), mapping.text(4));
                meter.visit(mapping_site)?;
                let found = closures.binary_search_by(|history| {
                    (
                        Some(history.family.name()),
                        Some(history.key.as_str()),
                        Some(history.edition.as_str()),
                    )
                        .cmp(&target)
                });
                if let Ok(found) = found {
                    declared_closures.push(clone_closure(&closures[found], mapping_site, meter)?);
                }
            }
            generations.push(OwnedGeneration {
                key: copy_text(key, site, meter)?,
                declaration: Generation {
                    scope: parse_scope(key, site, meter)?,
                    ordinal,
                    minimum: unsigned_cell(row, 4, site, meter)?,
                    label: copy_text(text_cell(row, 2, site, meter)?, site, meter)?,
                    versions,
                    closures: declared_closures,
                },
                version_order: Vec::new(),
                closure_order: Vec::new(),
            });
        }
        for owned in &mut generations {
            let site = AuditSite::row(
                "pn_admission_generations",
                &[
                    SitePart::Scope(&owned.declaration.scope),
                    SitePart::Integer(owned.declaration.ordinal),
                ],
            );
            meter.reserve(&mut owned.version_order, owned.declaration.versions.len(), site)?;
            owned.version_order.extend(0..owned.declaration.versions.len());
            meter.reserve(&mut owned.closure_order, owned.declaration.closures.len(), site)?;
            owned.closure_order.extend(0..owned.declaration.closures.len());
        }
        let mut scopes = Vec::new();
        meter.reserve(&mut scopes, arena.domains[3].len(), AuditSite::NotRead)?;
        for row in &arena.domains[3] {
            let site = row.site(&SPECS[3]);
            meter.visit(site)?;
            let key = text_cell(row, 0, site, meter)?;
            scopes.push(OwnedScope {
                key: copy_text(key, site, meter)?,
                scope: parse_scope(key, site, meter)?,
                pointer: identity_cell(row, 1, site, meter)?,
            });
        }
        let mut results = Vec::new();
        meter.reserve(&mut results, arena.domains[4].len(), AuditSite::NotRead)?;
        for row in &arena.domains[4] {
            let site = row.site(&SPECS[4]);
            meter.visit(site)?;
            let key = text_cell(row, 0, site, meter)?;
            results.push(OwnedResult {
                key: copy_text(key, site, meter)?,
                scope: parse_scope(key, site, meter)?,
                identity: identity_cell(row, 1, site, meter)?,
                parent: optional_identity_cell(row, 3, site, meter)?,
                depth: unsigned_cell(row, 2, site, meter)?,
                segment: identity_cell(row, 6, site, meter)?,
                generation: unsigned_cell(row, 7, site, meter)?,
            });
        }
        let mut descriptors = Vec::new();
        meter.reserve(&mut descriptors, arena.domains[5].len(), AuditSite::NotRead)?;
        for row in &arena.domains[5] {
            let site = row.site(&SPECS[5]);
            meter.visit(site)?;
            let key = text_cell(row, 0, site, meter)?;
            descriptors.push(OwnedDescriptor {
                key: copy_text(key, site, meter)?,
                scope: parse_scope(key, site, meter)?,
                segment: identity_cell(row, 1, site, meter)?,
                start: unsigned_cell(row, 2, site, meter)?,
                parent_segment: optional_identity_cell(row, 3, site, meter)?,
                fork: optional_identity_cell(row, 4, site, meter)?,
                cutoff: unsigned_cell(row, 5, site, meter)?,
            });
        }
        let mut vintages = Vec::new();
        meter.reserve(&mut vintages, arena.domains[10].len(), AuditSite::NotRead)?;
        for row in &arena.domains[10] {
            let site = row.site(&SPECS[10]);
            meter.visit(site)?;
            let sequence = text_cell(row, 3, site, meter)?
                .parse::<u64>()
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            vintages.push(OwnedVintage {
                act: pn_records::ActId {
                    author: copy_text(text_cell(row, 2, site, meter)?, site, meter)?,
                    sequence,
                    family: copy_text(text_cell(row, 4, site, meter)?, site, meter)?,
                },
                bytes: std::cell::OnceCell::new(),
            });
        }
        Ok(Self {
            arena,
            histories,
            generations,
            scopes,
            results,
            descriptors,
            vintages,
        })
    }
}

impl<'a> AuditSource<'a> for ServerSource {
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn check_identity(&self, _meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn collect(&'a self, meter: &mut AuditMeter) -> Result<Collected<'a>, AuditFailure> {
        let mut generations = Vec::new();
        meter.reserve(&mut generations, self.generations.len(), AuditSite::NotRead)?;
        for owned in &self.generations {
            let declaration = &owned.declaration;
            let site = AuditSite::row(
                "pn_admission_generations",
                &[SitePart::Scope(&declaration.scope), SitePart::Integer(declaration.ordinal)],
            );
            meter.visit(site)?;
            let mut versions = Vec::new();
            meter.reserve(&mut versions, declaration.versions.len(), site)?;
            versions.extend(&declaration.versions);
            let mut closures = Vec::new();
            meter.reserve(&mut closures, declaration.closures.len(), site)?;
            closures.extend(&declaration.closures);
            generations.push(RawGeneration {
                key: copy_text(&owned.key, site, meter)?,
                declaration,
                versions,
                closures,
            });
        }
        let mut scopes = Vec::new();
        meter.reserve(&mut scopes, self.scopes.len(), AuditSite::NotRead)?;
        for owned in &self.scopes {
            let site = AuditSite::row("pn_epoch_scopes", &[SitePart::Scope(&owned.scope)]);
            meter.visit(site)?;
            scopes.push(RawScope {
                key: copy_text(&owned.key, site, meter)?,
                scope: &owned.scope,
                pointer: owned.pointer,
            });
        }
        let mut results = Vec::new();
        meter.reserve(&mut results, self.results.len(), AuditSite::NotRead)?;
        for owned in &self.results {
            let site = AuditSite::row(
                "pn_epoch_results",
                &[SitePart::Scope(&owned.scope), SitePart::Identity(owned.identity)],
            );
            meter.visit(site)?;
            meter.visit(site)?;
            let label = self
                .generations
                .binary_search_by(|generation| generation.key.cmp(&owned.key))
                .ok()
                .map_or("", |at| self.generations[at].declaration.label.as_str());
            results.push(RawResult {
                key: copy_text(&owned.key, site, meter)?,
                scope: &owned.scope,
                identity: owned.identity,
                parent: owned.parent,
                depth: owned.depth,
                segment: owned.segment,
                label,
                generation: owned.generation,
                content: std::cell::OnceCell::new(),
            });
        }
        Ok(Collected {
            generations,
            scopes,
            results,
            descriptors: Vec::new(),
        })
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn check_shapes(&self, _rows: &Collected<'_>, _meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn check_generation_indices(&self, rows: &mut Collected<'a>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        for (at, domain) in [(1, &self.arena.domains[1]), (2, &self.arena.domains[2])] {
            let history = if at == 1 {
                &self.arena.domains[6]
            } else {
                &self.arena.domains[7]
            };
            for mapping in domain {
                let site = mapping.site(&SPECS[at]);
                meter.visit(site)?;
                let scope = text_cell(mapping, 0, site, meter)?;
                let ordinal = unsigned_cell(mapping, 1, site, meter)?;
                meter.visit(site)?;
                if rows
                    .generations
                    .binary_search_by(|generation| {
                        (generation.key.as_str(), generation.declaration.ordinal).cmp(&(scope, ordinal))
                    })
                    .is_err()
                {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
                let target = (mapping.text(2), mapping.text(3), mapping.text(4));
                meter.visit(site)?;
                if history
                    .binary_search_by(|row| (row.text(0), row.text(1), row.text(2)).cmp(&target))
                    .is_err()
                {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
        for generation in &rows.generations {
            let site = AuditSite::row(
                "pn_admission_generations",
                &[
                    SitePart::Scope(&generation.declaration.scope),
                    SitePart::Integer(generation.declaration.ordinal),
                ],
            );
            meter.visit(site)?;
            let key = &generation.key;
            let ordinal =
                i64::try_from(generation.declaration.ordinal).map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            meter.visit(site)?;
            let header_at = self.arena.domains[0]
                .binary_search_by(|row| (row.text(0), row.integer(1)).cmp(&(Some(key.as_str()), Some(ordinal))))
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            let header = &self.arena.domains[0][header_at];
            if header.integer(5).and_then(|n| usize::try_from(n).ok()) != Some(generation.declaration.versions.len())
                || header.integer(6).and_then(|n| usize::try_from(n).ok()) != Some(generation.declaration.closures.len())
            {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        for (history_at, mapping_at) in [(6, 1), (7, 2)] {
            let mappings = &self.arena.domains[mapping_at];
            for history in &self.arena.domains[history_at] {
                let site = history.site(&SPECS[history_at]);
                meter.visit(site)?;
                let family = text_cell(history, 0, site, meter)?;
                if !matches!(family, "rule" | "constants") {
                    continue;
                }
                let target = (history.text(0), history.text(1), history.text(2));
                meter.visit(site)?;
                if mappings
                    .binary_search_by(|row| (row.text(2), row.text(3), row.text(4)).cmp(&target))
                    .is_err()
                {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
        for (row, version) in self.arena.domains[6].iter().zip(&self.histories) {
            let site = row.site(&SPECS[6]);
            meter.visit(site)?;
            if let Some(payload) = &version.payload {
                let validated = crate::storage::tree::server::spans::Validated::audit(&payload.bytes, meter, site)?;
                crate::storage::tree::server::spans::history_payload(
                    &validated,
                    version.family,
                    &payload.bytes,
                    payload.digest,
                    payload.disclosure,
                )
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            }
        }
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn collect_descriptors(&'a self, rows: &mut Collected<'a>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        meter.reserve(&mut rows.descriptors, self.descriptors.len(), AuditSite::NotRead)?;
        for owned in &self.descriptors {
            let site = AuditSite::row(
                "pn_epoch_branches",
                &[SitePart::Scope(&owned.scope), SitePart::Identity(owned.segment)],
            );
            meter.visit(site)?;
            rows.descriptors.push(RawDescriptor {
                key: copy_text(&owned.key, site, meter)?,
                scope: &owned.scope,
                segment: owned.segment,
                first: owned.segment,
                start: owned.start,
                parent_segment: owned.parent_segment,
                fork: owned.fork,
                cutoff: owned.cutoff,
            });
        }
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn check_reference_index(&self, _rows: &Collected<'_>, _meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn check_segments(
        &self,
        rows: &Collected<'_>,
        _children: &[Vec<usize>],
        _segment_order: &[usize],
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure> {
        for row in &self.arena.domains[4] {
            let site = row.site(&SPECS[4]);
            meter.visit(site)?;
            let depth = unsigned_cell(row, 2, site, meter)?;
            let parent = optional_identity_cell(row, 3, site, meter)?;
            let parent_depth = match row.cells.get(4) {
                Some(Cell::Integer(value)) => u64::try_from(*value).ok(),
                _ => None,
            };
            let parent_segment = optional_identity_cell(row, 5, site, meter)?;
            if (depth == 1) != parent.is_none()
                || (depth == 1) != parent_depth.is_none()
                || (depth == 1) != parent_segment.is_none()
                || parent_depth.is_some_and(|value| value.checked_add(1) != Some(depth))
            {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        for at in 8..=12 {
            for detail in &self.arena.domains[at] {
                let site = detail.site(&SPECS[at]);
                meter.visit(site)?;
                let scope = text_cell(detail, 0, site, meter)?;
                let identity = detail
                    .bytes(1)
                    .ok_or_else(|| meter.refused(StorageError::CorruptHistory, site))?;
                meter.visit(site)?;
                let found = rows
                    .results
                    .binary_search_by(|row| (row.key.as_str(), row.identity.as_slice()).cmp(&(scope, identity)));
                let Ok(found) = found else {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                };
                if at == 12 {
                    let owner = &rows.results[found];
                    if detail.bytes(5) != Some(owner.segment.as_slice())
                        || detail.integer(6).and_then(|value| u64::try_from(value).ok()) != Some(owner.depth)
                    {
                        return Err(meter.refused(StorageError::CorruptHistory, site));
                    }
                }
                if at == 11 || at == 12 {
                    let key = (
                        detail.text(0),
                        detail.bytes(1),
                        detail.text(2),
                        detail.text(3),
                        detail.text(4),
                    );
                    meter.visit(site)?;
                    if self.arena.domains[10]
                        .binary_search_by(|header| {
                            (
                                header.text(0),
                                header.bytes(1),
                                header.text(2),
                                header.text(3),
                                header.text(4),
                            )
                                .cmp(&key)
                        })
                        .is_err()
                    {
                        return Err(meter.refused(StorageError::CorruptHistory, site));
                    }
                }
            }
        }
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn check_content(
        &self,
        row: &RawResult<'_>,
        parent: Option<&RawResult<'_>>,
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        if let Some(parent) = parent {
            let child = crate::storage::tree::server::spans::Validated::audit(row.content().package.as_ref(), meter, site)?;
            let prior = crate::storage::tree::server::spans::Validated::audit(parent.content().package.as_ref(), meter, site)?;
            let valid = crate::storage::tree::server::projection::extends_match(&child, &prior)
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            if !valid {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        Self::position(row, parent, meter)?;
        Ok(())
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn prepare_content(
        &'a self,
        row: &RawResult<'a>,
        _parent: Option<&RawResult<'a>>,
        meter: &mut AuditMeter,
    ) -> Result<Option<RawContent<'a>>, AuditFailure> {
        let site = AuditSite::row(
            "pn_epoch_results",
            &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
        );
        let header = self.header(row, meter)?;
        let package = self.package(row, header, meter)?;
        let document = crate::storage::tree::server::spans::Validated::audit(&package, meter, site)?;
        let (selections, observations) = self.selections(row, header, meter)?;
        let local = self.local(row, header, meter)?;
        let expected_debits = crate::storage::tree::server::projection::expected_debits_audit(&document, meter, site)?;
        if unsigned_cell(header, 11, site, meter)? != u64::try_from(expected_debits.len()).unwrap_or(u64::MAX) {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        crate::storage::tree::server::projection::validate_audit(
            row.scope,
            (row.identity, row.depth),
            &document,
            &selections,
            &expected_debits,
            meter,
            site,
        )?;
        let mut selection_order = Vec::new();
        meter.reserve(&mut selection_order, selections.len(), site)?;
        selection_order.extend(0..selections.len());
        selection_order.sort_unstable_by(|&a, &b| {
            super::super::coordinate(selections[a].use_.as_ref()).cmp(&super::super::coordinate(selections[b].use_.as_ref()))
        });
        Ok(Some(RawContent {
            package: std::borrow::Cow::Owned(package),
            selections,
            selection_order,
            observations,
            local,
            expected_debits,
        }))
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn context(&self, row: &RawResult<'_>, meter: &mut AuditMeter) -> Result<pn_interchange::Value, AuditFailure> {
        Self::position(row, None, meter)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn collect_observations(&'a self, meter: &mut AuditMeter) -> Result<Vec<RawObservation<'a>>, AuditFailure> {
        let count = self
            .histories
            .iter()
            .filter(|version| !matches!(version.family, Family::Rule | Family::Constants))
            .count();
        let mut observations = Vec::new();
        meter.reserve(&mut observations, count, AuditSite::NotRead)?;
        for version in &self.histories {
            if matches!(version.family, Family::Rule | Family::Constants) {
                continue;
            }
            let site = AuditSite::row(
                "pn_versions",
                &[
                    SitePart::Text(version.family.name(), 21),
                    SitePart::Text(&version.key, 1024),
                    SitePart::Text(&version.edition, 1024),
                ],
            );
            meter.visit(site)?;
            observations.push(RawObservation {
                family: version.family,
                key: &version.key,
                edition: &version.edition,
                version,
            });
        }
        observations.sort_unstable_by(|a, b| (a.family, a.key, a.edition).cmp(&(b.family, b.key, b.edition)));
        Ok(observations)
    }
    /// Justified: Private field access or reconciliation inherits the enclosing observed position or server audit operation.
    fn observation_relation(&self) -> &'static str {
        "pn_versions"
    }
}

pub(in crate::storage::tree) async fn reconcile_tx(
    transaction: &StatementTransaction<'_>,
    meter: &mut AuditMeter,
    page_rows: usize,
) -> Result<AuditInventory, AuditFailure> {
    let source = ServerSource::new(scan(transaction, meter, page_rows).await?, meter)?;
    let graph = super::prepare_graph(&source, meter)?;
    let checked = super::check_graph_content(&source, graph, meter)?;
    check_enumeration(
        transaction,
        &checked.graph.rows,
        &checked.graph.ranks.children,
        meter,
        page_rows,
    )
    .await?;
    super::finish_audit(checked, meter)
}

async fn enumeration_exists(
    transaction: &StatementTransaction<'_>,
    meter: &mut AuditMeter,
    scope: &str,
    identity: Identity,
    child: bool,
    site: AuditSite<'_>,
) -> Result<bool, AuditFailure> {
    meter.visit(site)?;
    meter.admit_delivery(1, 7, site)?;
    let statement = if child { Statement::HasChild } else { Statement::HasEpoch };
    let rows = observed(transaction.query(statement, &[&scope, &&identity[..]]))
        .await
        .map_err(|error| meter.refused(error, site))?;
    if rows.len() != 1 || rows[0].len() != 1 {
        return Err(meter.refused(StorageError::CorruptHistory, site));
    }
    rows[0]
        .try_get(0)
        .map_err(|_| meter.refused(StorageError::CorruptHistory, site))
}

async fn enumeration_page(
    transaction: &StatementTransaction<'_>,
    meter: &mut AuditMeter,
    scope: &str,
    parent: Option<Identity>,
    expected: &[Identity],
    page: (usize, Statement),
    site: AuditSite<'_>,
) -> Result<(), AuditFailure> {
    let (page_rows, statement) = page;
    let mut after: Option<Identity> = None;
    let mut matched = 0usize;
    loop {
        if let Some(parent) = parent
            && !enumeration_exists(transaction, meter, scope, parent, false, site).await?
        {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        meter.visit(site)?;
        let chosen = page_rows.min(meter.remaining_rows());
        if chosen == 0 {
            return Err(meter.refused(StorageError::ReadLimit, site));
        }
        let ceiling = i64::try_from(chosen).map_err(|_| meter.refused(StorageError::ReadLimit, site))?;
        meter.admit_delivery(chosen, 50, site)?;
        let boundary = after.as_ref().map(|id| &id[..]);
        #[cfg(test)]
        crate::storage::tree::server::tests::fetched();
        let rows = match parent {
            Some(parent) => observed(transaction.query(statement, &[&scope, &boundary, &ceiling, &&parent[..]])).await,
            None => observed(transaction.query(statement, &[&scope, &boundary, &ceiling])).await,
        }
        .map_err(|error| meter.refused(error, site))?;
        if rows.len() > chosen {
            return Err(meter.refused(StorageError::CorruptHistory, site));
        }
        meter.release_delivery(chosen - rows.len(), 50);
        let empty = rows.is_empty();
        for row in &rows {
            let bytes = row
                .try_get::<_, &[u8]>(0)
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            let len = row
                .try_get::<_, i64>(1)
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            let identity: Identity = bytes
                .try_into()
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            if len != 32 || after.is_some_and(|prior| prior >= identity) || expected.get(matched) != Some(&identity) {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            after = Some(identity);
            matched += 1;
        }
        if empty {
            break;
        }
    }
    if matched != expected.len() {
        return Err(meter.refused(StorageError::CorruptHistory, site));
    }
    Ok(())
}

async fn check_enumeration(
    transaction: &StatementTransaction<'_>,
    rows: &Collected<'_>,
    children: &[Vec<usize>],
    meter: &mut AuditMeter,
    page_rows: usize,
) -> Result<(), AuditFailure> {
    for scope in &rows.scopes {
        let site = AuditSite::row("pn_epoch_scopes", &[SitePart::Scope(scope.scope)]);
        meter.visit(site)?;
        let first = rows.results.partition_point(|row| row.key < scope.key);
        meter.visit(site)?;
        let last = rows.results.partition_point(|row| row.key <= scope.key);
        let in_scope = &rows.results[first..last];
        let mut candidates = Vec::new();
        meter.reserve(&mut candidates, in_scope.len(), site)?;
        for row in in_scope {
            candidates.push(row.identity);
        }
        candidates.sort_unstable();
        enumeration_page(
            transaction,
            meter,
            &scope.key,
            None,
            &candidates,
            (page_rows, Statement::ReadResultCandidates),
            site,
        )
        .await?;
        let mut roots = Vec::new();
        meter.reserve(&mut roots, in_scope.len(), site)?;
        for row in in_scope.iter().filter(|row| row.parent.is_none()) {
            roots.push(row.identity);
        }
        roots.sort_unstable();
        enumeration_page(
            transaction,
            meter,
            &scope.key,
            None,
            &roots,
            (page_rows, Statement::ReadRoots),
            site,
        )
        .await?;
        for (offset, row) in in_scope.iter().enumerate() {
            let row_site = AuditSite::row(
                "pn_epoch_results",
                &[SitePart::Scope(row.scope), SitePart::Identity(row.identity)],
            );
            let expected = &children[first + offset];
            let has_child = enumeration_exists(transaction, meter, &scope.key, row.identity, true, row_site).await?;
            if has_child == expected.is_empty() {
                return Err(meter.refused(StorageError::CorruptHistory, row_site));
            }
            let mut child_ids = Vec::new();
            meter.reserve(&mut child_ids, expected.len(), row_site)?;
            for &child in expected {
                child_ids.push(rows.results[child].identity);
            }
            child_ids.sort_unstable();
            enumeration_page(
                transaction,
                meter,
                &scope.key,
                Some(row.identity),
                &child_ids,
                (page_rows, Statement::ReadChildren),
                row_site,
            )
            .await?;
        }
    }
    Ok(())
}
