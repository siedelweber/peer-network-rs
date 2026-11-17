//! Closed effective-history storage; no executable opens this library surface.
//! (´def:host:effective-storage´)
use crate::{Cause, ServerError, Session, storage_payload as encoding};
use pn_interchange::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub use crate::admitted_result::{AdmittedEpoch, CarrierError, DebitKey, DebitVintage, DeclarationUse, EpochKey, EpochScope};

/// Permanent public payload recipe, distinct from the disclosure commitment domain.
/// (´def:host:effective-storage´)
pub const PAYLOAD_RECIPE: &str = "pn-host/storage-payload/v1";
/// Permanent digest recipe for the complete validated recognition disclosure.
/// (´def:host:effective-storage´)
pub const DISCLOSURE_RECIPE: &str = "pn-host/recognition-disclosure/v1";
const SCHEMA: &str = "pn-host/effective-history/v1";
const MAX_PACKAGE: usize = 262_144;

/// The closed set of families this storage slice can carry.
/// (´def:host:effective-storage´)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Constants,
    Rule,
    MarkerPolicy,
    Lineage,
    BurnPublication,
    UnsettledRecognition,
}
impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Constants => "constants",
            Self::Rule => "rule",
            Self::MarkerPolicy => "marker-policy",
            Self::Lineage => "lineage",
            Self::BurnPublication => "burn-publication",
            Self::UnsettledRecognition => "unsettled-recognition",
        }
    }
}

/// Bounded storage failure, never a mathematical verdict or a driver diagnostic.
/// (´def:host:effective-storage´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    Representation,
    SchemaIdentity,
    IndexDefinition,
    Transport,
    Server(ServerError),
    CorruptHistory,
    EditionConflict,
    Predecessor,
    Gap,
    Overlap,
    Retroactive,
    MissingRequired,
    Injected,
    CommitUnknown,
    EpochResultHeld,
    MissingSelectedVersion,
    SelectedContentMismatch,
    SelectedVersionNotEffective,
    EpochConflict,
    DebitConflict,
    HistoricalSelectionConflict,
    ReadLimit,
}

fn classified<T>(result: Result<T, StorageError>) -> Result<T, StorageError> {
    if let Err(cause) = &result
        && !matches!(
            cause,
            StorageError::Transport | StorageError::CommitUnknown | StorageError::Injected
        )
    {
        metrics::counter!("host__root__sig__design__storage__refusals").increment(1);
        tracing::event!(tracing::Level::TRACE, outcome = "refusal");
    }
    result
}

struct TransactionMeter {
    started: std::time::Instant,
    finished: bool,
}
impl TransactionMeter {
    fn new() -> Self {
        metrics::gauge!("host__root__sig__design__storage__active_transactions").increment(1.0);
        Self {
            started: std::time::Instant::now(),
            finished: false,
        }
    }
    fn commit(&mut self) {
        self.finished = true;
        metrics::counter!("host__root__sig__design__storage__commits").increment(1);
    }
}
impl Drop for TransactionMeter {
    /// Justified: Meter cleanup inherits the storage transaction and emits no recursive span; rollback counts abandoned transaction handles, not a claim that a lost acknowledgement rolled back.
    fn drop(&mut self) {
        metrics::gauge!("host__root__sig__design__storage__active_transactions").decrement(1.0);
        metrics::histogram!("host__root__sig__design__storage__transaction_elapsed_seconds")
            .record(self.started.elapsed().as_secs_f64());
        if !self.finished {
            metrics::counter!("host__root__sig__design__storage__rollbacks").increment(1);
        }
    }
}
struct QueueMeter;
impl QueueMeter {
    fn new() -> Self {
        metrics::gauge!("host__root__sig__design__storage__queue_depth").increment(1.0);
        Self
    }
}
impl Drop for QueueMeter {
    /// Justified: Queue accounting inherits the pending storage lock operation, including cancellation.
    fn drop(&mut self) {
        metrics::gauge!("host__root__sig__design__storage__queue_depth").decrement(1.0);
    }
}

/// Canonical public bytes produced only from this slice's validated carriers.
/// (´def:host:effective-storage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    family: Family,
    bytes: Vec<u8>,
    digest: [u8; 32],
    disclosure: Option<[u8; 32]>,
}
pub(crate) fn digest(recipe: &str, bytes: &[u8]) -> [u8; 32] {
    let mut state = Sha256::new();
    state.update(recipe.as_bytes());
    state.update([0]);
    state.update(bytes);
    state.finalize().into()
}
fn verify_payload(family: Family, bytes: &[u8], disclosure: Option<&[u8]>) -> Result<(), StorageError> {
    let value = Value::from_canonical_bytes(bytes).map_err(|_| StorageError::CorruptHistory)?;
    let Value::Array(envelope) = value else {
        return Err(StorageError::CorruptHistory);
    };
    let [recipe, kind, body] = envelope.as_slice() else {
        return Err(StorageError::CorruptHistory);
    };
    if *recipe != encoding::text(PAYLOAD_RECIPE) || *kind != encoding::text(family.name()) {
        return Err(StorageError::CorruptHistory);
    }
    if family == Family::UnsettledRecognition {
        let Value::Array(fields) = body else {
            return Err(StorageError::CorruptHistory);
        };
        let [recipe, Value::Bytes(stored), input, _] = fields.as_slice() else {
            return Err(StorageError::CorruptHistory);
        };
        let expected = digest(DISCLOSURE_RECIPE, &input.to_canonical_bytes());
        if *recipe != encoding::text(DISCLOSURE_RECIPE)
            || stored.as_slice() != expected
            || disclosure != Some(expected.as_slice())
        {
            return Err(StorageError::CorruptHistory);
        }
    } else if disclosure.is_some() {
        return Err(StorageError::CorruptHistory);
    }
    Ok(())
}
impl Payload {
    pub(crate) fn encoded(family: Family, value: Value, disclosure: Option<[u8; 32]>) -> Result<Self, StorageError> {
        let bytes = encoding::array([encoding::text(PAYLOAD_RECIPE), encoding::text(family.name()), value]).to_canonical_bytes();
        if bytes.len() > MAX_PACKAGE {
            return classified(Err(StorageError::Representation));
        }
        metrics::counter!("host__root__sig__design__storage__encoded_bytes").increment(bytes.len() as u64);
        metrics::histogram!("host__root__sig__design__storage__package_bytes").record(f64::from(
            u32::try_from(bytes.len()).map_err(|_| StorageError::Representation)?,
        ));
        Ok(Self {
            family,
            digest: digest(PAYLOAD_RECIPE, &bytes),
            bytes,
            disclosure,
        })
    }
    /// Retain a validated constants edition, its source definitions and exact floor.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses a package exceeding the declared bound.
    pub fn constants(value: &pn_records::constants::ConstantsEdition) -> Result<Self, StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::Payload::constants", value);
        let result = Self::encoded(Family::Constants, encoding::constants(value), None);
        span.finish(&result);
        result
    }
    /// Retain an opaque public rule without inventing its future domain semantics.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses a package exceeding the declared bound.
    pub fn rule(value: &Value) -> Result<Self, StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::Payload::rule", value);
        let result = Self::encoded(Family::Rule, value.clone(), None);
        span.finish(&result);
        result
    }
    /// Retain the declaration-bound policy with its checked burn publication.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses a package exceeding the declared bound.
    pub fn marker_policy(value: &pn_records::burn::ValidatedPolicy) -> Result<Self, StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::Payload::marker_policy", value);
        let (policy, burn) = value.disclosure();
        let result = Self::encoded(
            Family::MarkerPolicy,
            encoding::array([encoding::policy(policy), encoding::publication(burn)]),
            None,
        );
        span.finish(&result);
        result
    }
    /// Retain all disclosed candidates, records, policy and publication, including refused candidates.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses a package exceeding the declared bound.
    pub fn lineage(value: &pn_records::burn::ValidatedMarkerHistory) -> Result<Self, StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::Payload::lineage", value);
        let result = Self::encoded(Family::Lineage, encoding::disclosure(value), None);
        span.finish(&result);
        result
    }
    /// Retain sampled amounts only as their validated publication, never as settled burn.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses a package exceeding the declared bound.
    pub fn burn_publication(value: &pn_records::burn::ValidatedBurn) -> Result<Self, StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::Payload::burn_publication", value);
        let result = Self::encoded(Family::BurnPublication, encoding::publication(value.publication()), None);
        span.finish(&result);
        result
    }
    /// Recompute recognition from its validated disclosure and retain both input and output.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses a package exceeding the declared bound; recognition refusal remains public evidence.
    pub fn recognition(value: &pn_records::burn::ValidatedMarkerHistory) -> Result<Self, StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::Payload::recognition", value);
        let input = encoding::disclosure(value);
        let commitment = digest(DISCLOSURE_RECIPE, &input.to_canonical_bytes());
        let output = pn_records::burn::recognize_markers(value);
        let result = Self::encoded(
            Family::UnsettledRecognition,
            encoding::array([
                encoding::text(DISCLOSURE_RECIPE),
                Value::Bytes(commitment.to_vec().into()),
                input,
                encoding::recognition(&output),
            ]),
            Some(commitment),
        );
        span.finish(&result);
        result
    }
    /// Borrow retained canonical bytes, without substituting a later encoder's output.
    /// (´def:host:effective-storage´)
    /// Justified: Immutable carrier access inherits its producing storage operation.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Borrow the payload commitment and optional validated-disclosure commitment.
    /// (´def:host:effective-storage´)
    /// Justified: Immutable carrier access inherits its producing storage operation.
    #[must_use]
    pub fn commitments(&self) -> (&[u8; 32], Option<&[u8; 32]>) {
        (&self.digest, self.disclosure.as_ref())
    }
}

/// One immutable public version. Absence is an explicit withdrawal payload.
/// (´def:host:effective-storage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub family: Family,
    pub key: String,
    pub edition: String,
    pub announced_at: u64,
    pub opens_at: u64,
    pub payload: Option<Payload>,
}
/// The predecessor and its proposed exclusive closing boundary.
/// (´def:host:effective-storage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Predecessor {
    pub edition: String,
    pub closes_at: u64,
}
/// A resolved version with its appended closure fact, never a mutable stored end field.
/// (´def:host:effective-storage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveRow {
    pub version: Version,
    pub closes_at: Option<u64>,
}
/// A single consistent boundary input retaining the selected identities and bytes.
/// (´def:host:effective-storage´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub at: u64,
    pub rows: Vec<EffectiveRow>,
}

mod admitted;
pub use admitted::{EpochRead, ReadBudget, RetainedDebit};

pub mod catalogue;
pub mod tree;

type History = BTreeMap<(Family, String), Vec<EffectiveRow>>;
fn stored_text(value: &str) -> Result<(), StorageError> {
    if value.contains('\0') {
        return Err(StorageError::Representation);
    }
    Ok(())
}
fn stored_act(value: &pn_records::ActId) -> Result<(), StorageError> {
    stored_text(&value.author)?;
    stored_text(&value.family)
}
fn stored_projection(references: &[DeclarationUse], debits: &[DebitVintage]) -> Result<(), StorageError> {
    for reference in references {
        stored_text(&reference.version.key)?;
        stored_text(&reference.version.edition)?;
    }
    for debit in debits {
        stored_act(&debit.key.act)?;
    }
    Ok(())
}
pub(crate) fn check(version: &Version) -> Result<(), StorageError> {
    stored_text(&version.key)?;
    stored_text(&version.edition)?;
    if version.key.is_empty()
        || version.edition.is_empty()
        || version.key.len() > 1024
        || version.edition.len() > 1024
        || version.opens_at > i64::MAX as u64
        || version.announced_at > version.opens_at
        || version.payload.as_ref().is_some_and(|p| p.family != version.family)
    {
        return Err(StorageError::Representation);
    }
    Ok(())
}
fn append(history: &mut History, version: Version, predecessor: Option<&Predecessor>) -> Result<bool, StorageError> {
    check(&version)?;
    let rows = history.entry((version.family, version.key.clone())).or_default();
    if let Some(prior) = rows.iter().find(|v| v.version.edition == version.edition) {
        return if prior.version == version {
            Ok(false)
        } else {
            Err(StorageError::EditionConflict)
        };
    }
    match (rows.last_mut(), predecessor) {
        (None, None) => {}
        (Some(prior), Some(expected)) => {
            if prior.version.edition != expected.edition || prior.closes_at.is_some() {
                return Err(StorageError::Predecessor);
            }
            if expected.closes_at < version.opens_at {
                return Err(StorageError::Gap);
            }
            if expected.closes_at > version.opens_at {
                return Err(StorageError::Overlap);
            }
            if version.opens_at <= prior.version.opens_at || version.announced_at < prior.version.announced_at {
                return Err(StorageError::Retroactive);
            }
            prior.closes_at = Some(version.opens_at);
        }
        _ => return Err(StorageError::Predecessor),
    }
    rows.push(EffectiveRow {
        version,
        closes_at: None,
    });
    Ok(true)
}
fn boundary(history: &History, at: u64, required: &[(Family, String)]) -> Result<Boundary, StorageError> {
    let mut rows = Vec::new();
    for versions in history.values() {
        let prior: Vec<_> = versions.iter().filter(|row| row.version.opens_at <= at).collect();
        if let Some(row) = prior.iter().max_by_key(|row| row.version.opens_at) {
            if row.closes_at.is_some_and(|end| end <= at)
                || prior.iter().filter(|r| r.closes_at.is_none_or(|end| at < end)).count() != 1
            {
                return Err(StorageError::CorruptHistory);
            }
            verify_row(row)?;
            rows.push((**row).clone());
        }
    }
    for (family, key) in required {
        if !rows
            .iter()
            .any(|row| row.version.family == *family && row.version.key == *key && row.version.payload.is_some())
        {
            return Err(StorageError::MissingRequired);
        }
    }
    Ok(Boundary { at, rows })
}

fn verify_row(row: &EffectiveRow) -> Result<(), StorageError> {
    check(&row.version).map_err(|_| StorageError::CorruptHistory)?;
    if let Some(payload) = &row.version.payload {
        if payload.bytes.len() > MAX_PACKAGE || payload.digest != digest(PAYLOAD_RECIPE, &payload.bytes) {
            return Err(StorageError::CorruptHistory);
        }
        verify_payload(
            row.version.family,
            &payload.bytes,
            payload.disclosure.as_ref().map(<[u8; 32]>::as_slice),
        )?;
    }
    Ok(())
}

/// Functional fast substitute for the same append-only storage contract.
/// (´def:host:effective-storage´)
#[derive(Debug, Default)]
pub struct MemoryStore {
    history: History,
    admitted: admitted::State,
}
impl MemoryStore {
    /// Append closure and successor as one functional replacement.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Returns a typed succession refusal without altering history.
    pub fn append_effective_successor(
        &mut self,
        version: Version,
        predecessor: Option<&Predecessor>,
    ) -> Result<bool, StorageError> {
        let span = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::MemoryStore::append_effective_successor",
            &(&version, predecessor),
        );
        let key = (version.family, version.key.clone());
        let mut next = History::new();
        if let Some(rows) = self.history.get(&key) {
            next.insert(key.clone(), rows.clone());
        }
        let result = classified(append(&mut next, version, predecessor).and_then(|changed| {
            let mut candidate = self.history.clone();
            if let Some(rows) = next.get(&key) {
                candidate.insert(key.clone(), rows.clone());
            }
            self.admitted.guard(&candidate)?;
            Ok(changed)
        }));
        if result.is_ok()
            && let Some(rows) = next.remove(&key)
        {
            self.history.insert(key, rows);
        }
        span.finish(&result);
        result
    }
    /// Resolve all keys in one immutable boundary snapshot.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses an absent required value or corrupted interval history.
    pub fn load_boundary(&self, at: u64, required: &[(Family, String)]) -> Result<Boundary, StorageError> {
        let span = cli_common::observation::scope(
            "HOST",
            "sig:design:storage",
            "storage::MemoryStore::load_boundary",
            &(at, required),
        );
        let result = classified(boundary(&self.history, at, required));
        span.finish(&result);
        result
    }
    /// Verify every retained payload and complete interval chain.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses corruption without interpreting damaged rows as absence.
    pub fn audit_history(&self) -> Result<(), StorageError> {
        let span = cli_common::observation::scope("HOST", "sig:design:storage", "storage::MemoryStore::audit_history", &());
        let result = (|| {
            for rows in self.history.values() {
                for row in rows {
                    verify_row(row)?;
                }
                if rows.windows(2).any(|pair| {
                    pair[0].closes_at != Some(pair[1].version.opens_at) || pair[0].version.opens_at >= pair[1].version.opens_at
                }) || rows.last().is_some_and(|row| row.closes_at.is_some())
                {
                    return Err(StorageError::CorruptHistory);
                }
            }
            Ok(())
        })();
        let result = classified(result);
        span.finish(&result);
        result
    }
}

// Closed statement vocabulary: only this module can construct a statement.
// The closed wrapper owns the driver spelling; consumers receive only rows
// of admitted statements and borrowed typed parameters, never a raw client.
type StatementRow = tokio_postgres::Row;
type StatementParameter<'a> = &'a (dyn tokio_postgres::types::ToSql + Sync);

#[derive(Clone, Copy)]
enum Statement {
    BootstrapLock,
    HasTables,
    HasIdentity,
    Create,
    SetIdentity,
    GetIdentity,
    EnsureIndexes,
    VerifyIndexes,
    CreateEpochStore,
    VerifyEpochStore,
    LockHistory,
    ReadHistory,
    ReadKey,
    ReadBoundary,
    Close,
    Insert,
    HasEpoch,
    HasChild,
    ReadRoots,
    ReadChildren,
    ReadResultCandidates,
    ReadScope,
    ReadEpoch,
    ReadEpochAsOf,
    ReadBranch,
    ReadEpochChunks,
    ReadAdmissionGeneration,
    ReadEpochDebitKeys,
    ReadDebit,
    ReadDebitChunks,
    ReadAdmissionClosures,
    ReadAdmissionVersions,
    ReadEpochUse,
    ReadEpochReferences,
}
impl Statement {
    const fn sql(self) -> &'static str {
        match self {
            Self::ReadEpochDebitKeys => {
                "SELECT substring(origin FROM 1 FOR 32),octet_length(origin)::bigint,origin_depth,CASE WHEN octet_length(author)<=1024 THEN author ELSE '' END,octet_length(author)::bigint,CASE WHEN octet_length(act_sequence)<=20 THEN act_sequence ELSE '' END,octet_length(act_sequence)::bigint,CASE WHEN octet_length(act_family)<=1024 THEN act_family ELSE '' END,octet_length(act_family)::bigint FROM public.pn_epoch_result_debits WHERE scope=$1 AND segment=$2 AND origin_depth BETWEEN $3 AND $4 ORDER BY author,length(act_sequence),act_sequence,act_family,origin LIMIT $5"
            }
            Self::ReadDebit => {
                "SELECT writing_boundary,vintage_bytes,vintage_chunks FROM public.pn_epoch_debits WHERE scope=$1 AND origin=$2 AND author=$3 AND act_sequence=$4 AND act_family=$5 LIMIT 1"
            }
            Self::ReadDebitChunks => {
                "SELECT ordinal,octet_length(bytes)::bigint,substring(bytes FROM 1 FOR 0x40000) FROM public.pn_epoch_debit_chunks WHERE scope=$1 AND origin=$2 AND author=$3 AND act_sequence=$4 AND act_family=$5 ORDER BY ordinal LIMIT $6"
            }
            Self::ReadAdmissionClosures => {
                "SELECT CASE WHEN octet_length(m.family)<=21 THEN m.family ELSE '' END,octet_length(m.family)::bigint,CASE WHEN octet_length(m.key)<=1024 THEN m.key ELSE '' END,octet_length(m.key)::bigint,CASE WHEN octet_length(m.edition)<=1024 THEN m.edition ELSE '' END,octet_length(m.edition)::bigint,c.closes,m.generation FROM public.pn_admission_closures m JOIN LATERAL (SELECT q.* FROM public.pn_closures q WHERE q.family=m.family COLLATE \"default\" AND q.family COLLATE \"C\"=m.family AND q.key=m.key COLLATE \"default\" AND q.key COLLATE \"C\"=m.key AND q.edition=m.edition COLLATE \"default\" AND q.edition COLLATE \"C\"=m.edition LIMIT 1) c ON true WHERE m.scope=$1 AND m.generation<=$2 AND m.family=$3 AND m.key=$4 AND ($5::text IS NULL OR m.edition>$5) ORDER BY m.edition LIMIT $6"
            }
            Self::ReadAdmissionVersions => {
                "SELECT CASE WHEN octet_length(v.family)<=21 THEN v.family ELSE '' END,octet_length(v.family)::bigint,CASE WHEN octet_length(v.key)<=1024 THEN v.key ELSE '' END,octet_length(v.key)::bigint,CASE WHEN octet_length(v.edition)<=1024 THEN v.edition ELSE '' END,octet_length(v.edition)::bigint,v.announced,v.opens,substring(v.payload FROM 1 FOR 0x40000),octet_length(v.payload)::bigint,substring(v.digest FROM 1 FOR 32),octet_length(v.digest)::bigint,substring(v.disclosure FROM 1 FOR 32),octet_length(v.disclosure)::bigint,m.generation FROM public.pn_admission_versions m JOIN LATERAL (SELECT q.* FROM public.pn_versions q WHERE q.family=m.family COLLATE \"default\" AND q.family COLLATE \"C\"=m.family AND q.key=m.key COLLATE \"default\" AND q.key COLLATE \"C\"=m.key AND q.edition=m.edition COLLATE \"default\" AND q.edition COLLATE \"C\"=m.edition LIMIT 1) v ON true WHERE m.scope=$1 AND m.generation<=$2 AND m.family=$3 AND m.key=$4 AND ($5::text IS NULL OR m.edition>$5) ORDER BY m.edition LIMIT $6"
            }
            Self::ReadEpochUse => {
                "SELECT r.selected_at,substring(r.judgement_origin FROM 1 FOR 32),octet_length(r.judgement_origin)::bigint,CASE WHEN octet_length(v.family)<=21 THEN v.family ELSE '' END,octet_length(v.family)::bigint,CASE WHEN octet_length(v.key)<=1024 THEN v.key ELSE '' END,octet_length(v.key)::bigint,CASE WHEN octet_length(v.edition)<=1024 THEN v.edition ELSE '' END,octet_length(v.edition)::bigint,v.announced,v.opens,substring(v.payload FROM 1 FOR 0x40000),octet_length(v.payload)::bigint,substring(v.digest FROM 1 FOR 32),octet_length(v.digest)::bigint,substring(v.disclosure FROM 1 FOR 32),octet_length(v.disclosure)::bigint FROM public.pn_epoch_references r JOIN LATERAL (SELECT q.* FROM public.pn_versions q WHERE q.family=r.family COLLATE \"default\" AND q.family COLLATE \"C\"=r.family AND q.key=r.key COLLATE \"default\" AND q.key COLLATE \"C\"=r.key AND q.edition=r.edition COLLATE \"default\" AND q.edition COLLATE \"C\"=r.edition LIMIT 1) v ON true WHERE r.scope=$1 AND r.identity=$2 AND r.selected_at=$3 AND r.family=$4 AND r.key=$5 LIMIT 1"
            }
            Self::ReadEpochReferences => {
                "SELECT r.selected_at,substring(r.judgement_origin FROM 1 FOR 32),octet_length(r.judgement_origin)::bigint,CASE WHEN octet_length(v.family)<=21 THEN v.family ELSE '' END,octet_length(v.family)::bigint,CASE WHEN octet_length(v.key)<=1024 THEN v.key ELSE '' END,octet_length(v.key)::bigint,CASE WHEN octet_length(v.edition)<=1024 THEN v.edition ELSE '' END,octet_length(v.edition)::bigint,v.announced,v.opens,substring(v.payload FROM 1 FOR 0x40000),octet_length(v.payload)::bigint,substring(v.digest FROM 1 FOR 32),octet_length(v.digest)::bigint,substring(v.disclosure FROM 1 FOR 32),octet_length(v.disclosure)::bigint FROM public.pn_epoch_references r JOIN LATERAL (SELECT q.* FROM public.pn_versions q WHERE q.family=r.family COLLATE \"default\" AND q.family COLLATE \"C\"=r.family AND q.key=r.key COLLATE \"default\" AND q.key COLLATE \"C\"=r.key AND q.edition=r.edition COLLATE \"default\" AND q.edition COLLATE \"C\"=r.edition LIMIT 1) v ON true WHERE r.scope=$1 AND r.identity=$2 ORDER BY r.selected_at,r.family,r.key LIMIT $3"
            }
            Self::ReadScope => {
                "SELECT substring(context_root FROM 1 FOR 32),octet_length(context_root)::bigint FROM public.pn_epoch_scopes WHERE scope=$1 LIMIT 1"
            }
            Self::ReadEpoch => {
                "SELECT substring(identity FROM 1 FOR 32),octet_length(identity)::bigint,depth,substring(parent FROM 1 FOR 32),octet_length(parent)::bigint,parent_depth,substring(parent_segment FROM 1 FOR 32),octet_length(parent_segment)::bigint,substring(segment FROM 1 FOR 32),octet_length(segment)::bigint,generation,package_bytes,package_chunks,reference_count,debit_count FROM public.pn_epoch_results WHERE scope=$1 AND identity=$2 LIMIT 1"
            }
            Self::ReadEpochAsOf => {
                "SELECT substring(identity FROM 1 FOR 32),octet_length(identity)::bigint,depth,substring(parent FROM 1 FOR 32),octet_length(parent)::bigint,parent_depth,substring(parent_segment FROM 1 FOR 32),octet_length(parent_segment)::bigint,substring(segment FROM 1 FOR 32),octet_length(segment)::bigint,generation,package_bytes,package_chunks,reference_count,debit_count FROM public.pn_epoch_results WHERE scope=$1 AND segment=$2 AND depth<=$3 ORDER BY depth DESC LIMIT 1"
            }
            Self::ReadBranch => {
                "SELECT substring(segment FROM 1 FOR 32),octet_length(segment)::bigint,start_depth,substring(parent_segment FROM 1 FOR 32),octet_length(parent_segment)::bigint,substring(fork_parent FROM 1 FOR 32),octet_length(fork_parent)::bigint,fork_depth FROM public.pn_epoch_branches WHERE scope=$1 AND segment=$2 LIMIT 1"
            }
            Self::ReadEpochChunks => {
                "SELECT ordinal,octet_length(bytes)::bigint,substring(bytes FROM 1 FOR 0x40000) FROM public.pn_epoch_package_chunks WHERE scope=$1 AND identity=$2 ORDER BY ordinal LIMIT $3"
            }
            Self::ReadAdmissionGeneration => {
                "SELECT generation,previous,minimum,version_count,closure_count,CASE WHEN octet_length(label)<=1024 THEN label ELSE '' END,octet_length(label)::bigint FROM public.pn_admission_generations WHERE scope=$1 AND generation=$2 LIMIT 1"
            }
            Self::HasEpoch => "SELECT EXISTS(SELECT 1 FROM public.pn_epoch_results WHERE scope=$1 AND identity=$2)",
            Self::HasChild => "SELECT EXISTS(SELECT 1 FROM public.pn_epoch_results WHERE scope=$1 AND parent=$2)",
            Self::ReadRoots => {
                "SELECT substring(identity FROM 1 FOR 32),octet_length(identity)::bigint FROM public.pn_epoch_results WHERE scope=$1 AND parent IS NULL AND ($2::bytea IS NULL OR identity>$2) ORDER BY parent,identity LIMIT $3"
            }
            Self::ReadChildren => {
                "SELECT substring(identity FROM 1 FOR 32),octet_length(identity)::bigint FROM public.pn_epoch_results WHERE scope=$1 AND parent=$4 AND ($2::bytea IS NULL OR identity>$2) ORDER BY identity LIMIT $3"
            }
            Self::ReadResultCandidates => {
                "SELECT substring(identity FROM 1 FOR 32),octet_length(identity)::bigint FROM public.pn_epoch_results WHERE scope=$1 AND ($2::bytea IS NULL OR identity>$2) ORDER BY identity LIMIT $3"
            }
            Self::CreateEpochStore => catalogue::CREATE,
            Self::VerifyEpochStore => catalogue::VERIFY,
            Self::BootstrapLock => "SELECT pg_advisory_xact_lock(73100481)",
            Self::HasTables => {
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND c.relkind IN ('r','p'))"
            }
            Self::HasIdentity => "SELECT to_regclass('public.pn_store_identity') IS NOT NULL",
            Self::Create => {
                "Create TABLE public.pn_store_identity(identity text PRIMARY KEY); Create TABLE public.pn_versions(family text NOT NULL, key text NOT NULL, edition text NOT NULL, announced bigint NOT NULL, opens bigint NOT NULL, payload bytea, digest bytea, disclosure bytea, PRIMARY KEY(family,key,edition), UNIQUE(family,key,opens)); Create INDEX pn_recognition_disclosure ON public.pn_versions(disclosure) WHERE family='unsettled-recognition'; Create TABLE public.pn_closures(family text NOT NULL, key text NOT NULL, edition text NOT NULL, closes bigint NOT NULL, PRIMARY KEY(family,key,edition), FOREIGN KEY(family,key,edition) REFERENCES public.pn_versions(family,key,edition));"
            }
            Self::SetIdentity => "Insert INTO public.pn_store_identity VALUES ($1)",
            Self::EnsureIndexes => {
                "DO $$ BEGIN IF to_regclass('public.pn_versions_opens') IS NULL THEN CREATE INDEX pn_versions_opens ON public.pn_versions(opens); END IF; IF to_regclass('public.pn_closures_closes') IS NULL THEN CREATE INDEX pn_closures_closes ON public.pn_closures(closes); END IF; END $$"
            }
            Self::VerifyIndexes => {
                "SELECT bool_and(COALESCE(t.relnamespace='public'::regnamespace AND t.relname=e.table_name AND a.attname=e.column_name AND i.indnkeyatts=1 AND i.indnatts=1 AND i.indoption[0]=0 AND i.indisvalid AND i.indisready AND NOT i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL AND am.amname='btree',false)) FROM (VALUES ('pn_versions_opens','pn_versions','opens'),('pn_closures_closes','pn_closures','closes')) AS e(index_name,table_name,column_name) LEFT JOIN pg_catalog.pg_class c ON c.relnamespace='public'::regnamespace AND c.relname=e.index_name LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid LEFT JOIN pg_catalog.pg_class t ON t.oid=i.indrelid LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=i.indkey[0] LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam"
            }
            Self::GetIdentity => "SELECT identity FROM public.pn_store_identity",
            Self::LockHistory => "LOCK TABLE public.pn_versions IN SHARE ROW EXCLUSIVE MODE",
            Self::ReadHistory => {
                "SELECT v.family,v.key,v.edition,v.announced,v.opens,v.payload,v.digest,v.disclosure,c.closes FROM public.pn_versions v LEFT JOIN public.pn_closures c USING(family,key,edition) ORDER BY v.family,v.key,v.opens"
            }
            Self::ReadKey => {
                "SELECT v.family,v.key,v.edition,v.announced,v.opens,v.payload,v.digest,v.disclosure,c.closes FROM public.pn_versions v LEFT JOIN public.pn_closures c USING(family,key,edition) WHERE v.family=$1 AND v.key=$2 ORDER BY v.opens"
            }
            Self::ReadBoundary => {
                "SELECT DISTINCT ON (v.family,v.key) v.family,v.key,v.edition,v.announced,v.opens,v.payload,v.digest,v.disclosure,c.closes,count(*) FILTER (WHERE c.closes IS NULL OR c.closes > $1) OVER (PARTITION BY v.family,v.key) FROM public.pn_versions v LEFT JOIN public.pn_closures c USING(family,key,edition) WHERE v.opens <= $1 ORDER BY v.family,v.key,v.opens DESC"
            }
            Self::Close => "Insert INTO public.pn_closures(family,key,edition,closes) VALUES($1,$2,$3,$4)",
            Self::Insert => {
                "Insert INTO public.pn_versions(family,key,edition,announced,opens,payload,digest,disclosure) VALUES($1,$2,$3,$4,$5,$6,$7,$8)"
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RequestState {
    answer: std::sync::Arc<std::sync::Mutex<Option<ServerError>>>,
    retired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    interval: std::sync::Arc<tokio::sync::Mutex<()>>,
    #[cfg(test)]
    events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
}

#[derive(Clone, Copy, Debug)]
enum RequestContext {
    Writer,
    Other,
    Commit,
}

fn completion(context: RequestContext, answer: Option<ServerError>) -> StorageError {
    match (context, answer) {
        (RequestContext::Commit, None) => StorageError::CommitUnknown,
        (RequestContext::Commit, Some(value)) if !value.took_no_effect() => StorageError::CommitUnknown,
        (RequestContext::Commit | RequestContext::Writer, Some(value))
            if value.took_no_effect() && value.cause() == Cause::ConstraintViolation =>
        {
            StorageError::CorruptHistory
        }
        (_, Some(value)) => StorageError::Server(value),
        (_, None) => StorageError::Transport,
    }
}

struct PendingRequest {
    state: RequestState,
    complete: bool,
}
impl Drop for PendingRequest {
    /// Justified: Pending request retirement inherits the enclosing storage operation and emits no content.
    fn drop(&mut self) {
        if !self.complete {
            self.state.retire();
        }
    }
}

impl RequestState {
    pub(crate) fn new(answer: std::sync::Arc<std::sync::Mutex<Option<ServerError>>>) -> Self {
        Self {
            answer,
            retired: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            interval: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
    fn retire(&self) {
        self.retired.store(true, std::sync::atomic::Ordering::Release);
        self.event("retire");
    }
    fn retired(&self) -> bool {
        self.retired.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn take(&self) -> Option<ServerError> {
        self.event("take");
        let operation = cli_common::observation::scope("HOST", "sig:design:storage", "Session::take_server_error", self);
        let result = self.answer.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        operation.finish(&result);
        result
    }
    fn event(&self, value: &'static str) {
        #[cfg(test)]
        self.events.lock().unwrap().push(value);
        #[cfg(not(test))]
        let _ = (self, value);
    }
    async fn request<T, E>(
        &self,
        context: RequestContext,
        future: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, StorageError> {
        let _interval = self.interval.lock().await;
        if self.retired() {
            self.event("release");
            return Err(StorageError::Transport);
        }
        if self.take().is_some() {
            self.retire();
            self.event("release");
            return Err(StorageError::Transport);
        }
        let mut pending = PendingRequest {
            state: self.clone(),
            complete: false,
        };
        self.event("submit");
        match future.await {
            Ok(value) => {
                pending.complete = true;
                drop(pending);
                self.event("release");
                Ok(value)
            }
            Err(_driver_error) => {
                let answer = self.take();
                let result = completion(context, answer);
                drop(pending);
                self.event("release");
                Err(result)
            }
        }
    }
    async fn cleanup<P, E>(&self, primary: P, future: impl std::future::Future<Output = Result<(), E>>) -> (P, bool) {
        let success = self.request(RequestContext::Other, future).await.is_ok();
        (primary, success)
    }
}

// The raw driver stays inside this wrapper; even other crate modules cannot issue SQL.
#[derive(Debug)]
pub(crate) struct StatementClient {
    raw: tokio_postgres::Client,
}
impl StatementClient {
    /// Justified: Private driver wrapping inherits `Session::connect`; it acquires no additional connection or public content.
    pub(crate) fn new(raw: tokio_postgres::Client) -> Self {
        Self { raw }
    }
    /// Justified: Connection-status access inherits the enclosing session operation and exposes no driver data.
    pub(crate) fn is_closed(&self) -> bool {
        self.raw.is_closed()
    }
    #[cfg(test)]
    pub(crate) fn fixture(&self) -> &tokio_postgres::Client {
        &self.raw
    }
    async fn transaction(&mut self, state: RequestState) -> Result<StatementTransaction<'_>, StorageError> {
        let transaction = state.request(RequestContext::Other, self.raw.transaction()).await?;
        Ok(StatementTransaction {
            raw: Some(transaction),
            state,
            ended: false,
            context: RequestContext::Writer,
        })
    }
    async fn snapshot(&mut self, state: RequestState) -> Result<StatementTransaction<'_>, StorageError> {
        let transaction = state
            .request(
                RequestContext::Other,
                self.raw
                    .build_transaction()
                    .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                    .read_only(true)
                    .start(),
            )
            .await?;
        Ok(StatementTransaction {
            raw: Some(transaction),
            state,
            ended: false,
            context: RequestContext::Other,
        })
    }
}
struct StatementTransaction<'a> {
    raw: Option<tokio_postgres::Transaction<'a>>,
    state: RequestState,
    ended: bool,
    context: RequestContext,
}
impl Drop for StatementTransaction<'_> {
    /// Justified: Unended transaction retirement inherits its caller's storage operation and emits no content.
    fn drop(&mut self) {
        if !self.ended {
            self.state.retire();
        }
    }
}
impl StatementTransaction<'_> {
    async fn query(
        &self,
        statement: Statement,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<tokio_postgres::Row>, StorageError> {
        self.state
            .request(self.context, self.raw.as_ref().unwrap().query(statement.sql(), params))
            .await
    }
    async fn query_one(
        &self,
        statement: Statement,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<tokio_postgres::Row, StorageError> {
        self.state
            .request(self.context, self.raw.as_ref().unwrap().query_one(statement.sql(), params))
            .await
    }
    async fn execute(
        &self,
        statement: Statement,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<u64, StorageError> {
        self.state
            .request(self.context, self.raw.as_ref().unwrap().execute(statement.sql(), params))
            .await
    }
    async fn batch_execute(&self, statement: Statement) -> Result<(), StorageError> {
        self.state
            .request(self.context, self.raw.as_ref().unwrap().batch_execute(statement.sql()))
            .await
    }
    async fn commit(mut self) -> Result<(), StorageError> {
        let result = self
            .state
            .request(RequestContext::Commit, self.raw.take().unwrap().commit())
            .await;
        if result.is_ok() {
            self.ended = true;
        }
        result
    }
    async fn refuse<P>(mut self, error: P) -> P {
        let (error, success) = self.state.cleanup(error, self.raw.take().unwrap().rollback()).await;
        self.ended = success;
        error
    }
}

/// PostgreSQL adapter; the raw session and statement vocabulary stay private.
/// (´def:host:effective-storage´)
#[derive(Debug)]
pub struct PostgresStore {
    session: Session,
}
impl PostgresStore {
    /// Reserved atomic epoch operation; no caller can construct its admitted input yet.
    /// (´open:host:admitted-epoch-result´)
    /// # Errors
    /// Always refuses while the admitted ledger/result carrier is held for bite 5.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::PostgresStore::commit_admitted_epoch",
            asynchronous = true
        ),
        ret
    )]
    pub async fn commit_admitted_epoch(&mut self, input: &AdmittedEpoch) -> Result<(), StorageError> {
        let _ = input;
        classified(Err(StorageError::EpochResultHeld))
    }
    /// Initialize only an empty database, or require the exact existing schema identity.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses foreign schema identity, mismatched index definitions or transport failure; missing declared indexes are added idempotently.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::PostgresStore::open_store",
            asynchronous = true
        ),
        ret
    )]
    pub async fn open_store(mut session: Session) -> Result<Self, StorageError> {
        classified(Self::open_inner(&mut session).await)?;
        Ok(Self { session })
    }
    async fn open_inner(session: &mut Session) -> Result<(), StorageError> {
        let mut meter = TransactionMeter::new();
        let transaction = session.client.transaction(session.store_requests.clone()).await?;
        let result = async {
            observed(transaction.query(Statement::BootstrapLock, &[])).await?;
            let exists: bool = observed(transaction.query_one(Statement::HasIdentity, &[])).await?.get(0);
            if !exists {
                let occupied: bool = observed(transaction.query_one(Statement::HasTables, &[])).await?.get(0);
                if occupied {
                    return Err(StorageError::SchemaIdentity);
                }
                observed(transaction.batch_execute(Statement::Create)).await?;
                observed(transaction.execute(Statement::SetIdentity, &[&SCHEMA])).await?;
            }
            let rows = observed(transaction.query(Statement::GetIdentity, &[])).await?;
            if rows.len() != 1 || rows[0].get::<_, String>(0) != SCHEMA {
                return Err(StorageError::SchemaIdentity);
            }
            observed(transaction.batch_execute(Statement::EnsureIndexes)).await?;
            let indexes_match: bool = observed(transaction.query_one(Statement::VerifyIndexes, &[])).await?.get(0);
            if !indexes_match {
                return Err(StorageError::IndexDefinition);
            }
            Ok::<_, StorageError>(())
        }
        .await;
        if let Err(error) = result {
            return Err(transaction.refuse(error).await);
        }
        transaction.commit().await?;
        meter.commit();
        Ok(())
    }
    /// Resolve complete immutable input under a repeatable-read snapshot.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses transport, corrupt history or missing required input, never choosing the newest row.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::PostgresStore::load_boundary",
            asynchronous = true
        ),
        ret
    )]
    pub async fn load_boundary(&mut self, at: u64, required: &[(Family, String)]) -> Result<Boundary, StorageError> {
        classified(self.load_inner(at, required).await)
    }
    async fn load_inner(&mut self, at: u64, required: &[(Family, String)]) -> Result<Boundary, StorageError> {
        let mut meter = TransactionMeter::new();
        let transaction = self.session.client.snapshot(self.session.store_requests.clone()).await?;
        let at_sql = i64::try_from(at).unwrap_or(i64::MAX);
        let result = async {
            let history = read(&transaction, Statement::ReadBoundary, &[&at_sql], false).await?;
            boundary(&history, at, required)
        }
        .await;
        if let Err(error) = result {
            return Err(transaction.refuse(error).await);
        }
        transaction.commit().await?;
        meter.commit();
        result
    }
    /// Verify every retained payload and complete interval chain in one snapshot.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Refuses corrupt history or a failed transport without substituting a boundary read.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::PostgresStore::audit_history",
            asynchronous = true
        ),
        ret
    )]
    pub async fn audit_history(&mut self) -> Result<(), StorageError> {
        let mut meter = TransactionMeter::new();
        let transaction = self.session.client.snapshot(self.session.store_requests.clone()).await?;
        let result = read(&transaction, Statement::ReadHistory, &[], true).await.map(|_| ());
        if let Err(error) = result {
            return classified(Err(transaction.refuse(error).await));
        }
        transaction.commit().await?;
        meter.commit();
        classified(result)
    }
    /// Serialize succession, appending closure and successor in the same transaction.
    /// (´def:host:effective-storage´)
    /// # Errors
    /// Returns bounded succession failures; a lost commit acknowledgement is explicitly unknown.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "storage::PostgresStore::append_effective_successor",
            asynchronous = true
        ),
        ret
    )]
    pub async fn append_effective_successor(
        &mut self,
        version: Version,
        predecessor: Option<&Predecessor>,
    ) -> Result<bool, StorageError> {
        classified(self.append_inner(version, predecessor, 0).await)
    }
    async fn append_inner(
        &mut self,
        version: Version,
        predecessor: Option<&Predecessor>,
        fault: u8,
    ) -> Result<bool, StorageError> {
        check(&version)?;
        metrics::counter!("host__root__sig__design__storage__successor_attempts").increment(1);
        let mut meter = TransactionMeter::new();
        let transaction = self.session.client.transaction(self.session.store_requests.clone()).await?;
        let result = async {
            let queue = QueueMeter::new();
            observed(transaction.batch_execute(Statement::LockHistory)).await?;
            drop(queue);
            let mut history = read(
                &transaction,
                Statement::ReadKey,
                &[&version.family.name(), &version.key],
                true,
            )
            .await?;
            if !append(&mut history, version.clone(), predecessor)? {
                metrics::counter!("host__root__sig__design__storage__retries").increment(1);
                return Ok(false);
            }
            let family = version.family.name();
            let opens = i64::try_from(version.opens_at).map_err(|_| StorageError::Representation)?;
            if let Some(prior) = predecessor {
                observed(transaction.execute(Statement::Close, &[&family, &version.key, &prior.edition, &opens])).await?;
            }
            if fault == 1 {
                return Err(StorageError::Injected);
            }
            let announced = i64::try_from(version.announced_at).map_err(|_| StorageError::Representation)?;
            let bytes = version.payload.as_ref().map(|v| v.bytes.as_slice());
            let digest = version.payload.as_ref().map(|v| v.digest.as_slice());
            let disclosure = version
                .payload
                .as_ref()
                .and_then(|v| v.disclosure.as_ref().map(<[u8; 32]>::as_slice));
            observed(transaction.execute(
                Statement::Insert,
                &[
                    &family,
                    &version.key,
                    &version.edition,
                    &announced,
                    &opens,
                    &bytes,
                    &digest,
                    &disclosure,
                ],
            ))
            .await?;
            if fault == 2 {
                return Err(StorageError::Injected);
            }
            Ok::<_, StorageError>(true)
        }
        .await;
        let success = match result {
            Ok(success) => success,
            Err(error) => return Err(transaction.refuse(error).await),
        };
        transaction.commit().await?;
        meter.commit();
        Ok(success)
    }
}
async fn observed<T>(future: impl std::future::Future<Output = Result<T, StorageError>>) -> Result<T, StorageError> {
    metrics::counter!("host__root__sig__design__storage__queries").increment(1);
    let started = std::time::Instant::now();
    let result = future.await;
    metrics::histogram!("host__root__sig__design__storage__query_elapsed_seconds").record(started.elapsed().as_secs_f64());
    result
}
async fn read(
    transaction: &StatementTransaction<'_>,
    statement: Statement,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    complete: bool,
) -> Result<History, StorageError> {
    let rows = observed(transaction.query(statement, params)).await?;
    let mut history = History::new();
    for row in rows {
        if matches!(statement, Statement::ReadBoundary) && row.get::<_, i64>(9) != 1 {
            return Err(StorageError::CorruptHistory);
        }
        let family = match row.get::<_, String>(0).as_str() {
            "constants" => Family::Constants,
            "rule" => Family::Rule,
            "marker-policy" => Family::MarkerPolicy,
            "lineage" => Family::Lineage,
            "burn-publication" => Family::BurnPublication,
            "unsettled-recognition" => Family::UnsettledRecognition,
            _ => return Err(StorageError::CorruptHistory),
        };
        let bytes: Option<Vec<u8>> = row.get(5);
        let saved: Option<Vec<u8>> = row.get(6);
        let disclosure: Option<Vec<u8>> = row.get(7);
        let payload = match (bytes, saved) {
            (None, None) if disclosure.is_none() => None,
            (Some(bytes), Some(saved)) => {
                if bytes.len() > MAX_PACKAGE || saved != digest(PAYLOAD_RECIPE, &bytes) {
                    return Err(StorageError::CorruptHistory);
                }
                verify_payload(family, &bytes, disclosure.as_deref())?;
                metrics::counter!("host__root__sig__design__storage__decoded_bytes").increment(bytes.len() as u64);
                Some(Payload {
                    family,
                    digest: digest(PAYLOAD_RECIPE, &bytes),
                    bytes,
                    disclosure: disclosure
                        .map(|v| v.try_into().map_err(|_| StorageError::CorruptHistory))
                        .transpose()?,
                })
            }
            _ => return Err(StorageError::CorruptHistory),
        };
        let version = Version {
            family,
            key: row.get(1),
            edition: row.get(2),
            announced_at: u64::try_from(row.get::<_, i64>(3)).map_err(|_| StorageError::CorruptHistory)?,
            opens_at: u64::try_from(row.get::<_, i64>(4)).map_err(|_| StorageError::CorruptHistory)?,
            payload,
        };
        check(&version).map_err(|_| StorageError::CorruptHistory)?;
        let closes_at = row
            .get::<_, Option<i64>>(8)
            .map(|v| u64::try_from(v).map_err(|_| StorageError::CorruptHistory))
            .transpose()?;
        let versions = history.entry((family, version.key.clone())).or_default();
        if let Some(previous) = versions.last() {
            let previous: &EffectiveRow = previous;
            if previous.closes_at != Some(version.opens_at) || previous.version.opens_at >= version.opens_at {
                return Err(StorageError::CorruptHistory);
            }
        }
        versions.push(EffectiveRow { version, closes_at });
    }
    if complete
        && history
            .values()
            .any(|rows| rows.last().is_some_and(|row| row.closes_at.is_some()))
    {
        return Err(StorageError::CorruptHistory);
    }
    Ok(history)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod declaration_census;

#[cfg(test)]
mod store_error_tests {
    use super::{RequestContext, RequestState, StatementTransaction, StorageError, completion};
    use crate::{Cause, ServerError};
    use std::sync::{Arc, Mutex};

    const CAUSES: [Cause; 14] = [
        Cause::ConstraintViolation,
        Cause::Conflict,
        Cause::Cancelled,
        Cause::Terminated,
        Cause::Unavailable,
        Cause::Resources,
        Cause::ReadOnly,
        Cause::LoginRejected,
        Cause::PermissionDenied,
        Cause::Misconfigured,
        Cause::StatementRejected,
        Cause::ServerFault,
        Cause::StorageDamaged,
        Cause::Unrecognized,
    ];

    fn state() -> RequestState {
        RequestState::new(Arc::new(Mutex::new(None)))
    }
    fn run(future: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future);
    }

    async fn failure(state: &RequestState, context: RequestContext, value: ServerError) -> StorageError {
        let answer = state.answer.clone();
        state
            .request(context, async move {
                *answer.lock().unwrap() = Some(value);
                Err::<(), ()>(())
            })
            .await
            .unwrap_err()
    }

    /// Claim: A failing request takes before submission, takes its closed answer, and retires before interval release.
    /// ´claim:host:store-error-request-order´
    /// ´test:unit:store-error-request-order´
    #[test]
    fn store_error_request_order() {
        run(async {
            let state = state();
            assert_eq!(
                failure(&state, RequestContext::Other, ServerError::Failed(Cause::Conflict)).await,
                StorageError::Server(ServerError::Failed(Cause::Conflict))
            );
            assert_eq!(*state.events.lock().unwrap(), ["take", "submit", "take", "retire", "release"]);
            assert!(state.retired());
        });
    }

    /// Claim: A pending answer prevents submission, returns Transport and retires the session before reuse.
    /// ´claim:host:store-error-pending-answer´
    /// ´test:unit:store-error-pending-answer´
    #[test]
    fn store_error_pending_answer() {
        run(async {
            let state = state();
            *state.answer.lock().unwrap() = Some(ServerError::Uncertain(Cause::Terminated));
            assert_eq!(
                state.request(RequestContext::Commit, async { Ok::<(), ()>(()) }).await,
                Err(StorageError::Transport)
            );
            assert_eq!(
                state.request(RequestContext::Other, async { Ok::<(), ()>(()) }).await,
                Err(StorageError::Transport)
            );
            assert!(state.retired());
            assert!(!state.events.lock().unwrap().contains(&"submit"));
        });
    }

    /// Claim: Both statement contexts map every closed form and cause by the recorded table.
    /// ´claim:host:store-error-statement-map´
    /// ´test:unit:store-error-statement-map´
    #[test]
    fn store_error_statement_map() {
        for context in [RequestContext::Writer, RequestContext::Other] {
            for cause in CAUSES {
                for value in [ServerError::Failed(cause), ServerError::Uncertain(cause)] {
                    let expected = if matches!(context, RequestContext::Writer)
                        && value == ServerError::Failed(Cause::ConstraintViolation)
                    {
                        StorageError::CorruptHistory
                    } else {
                        StorageError::Server(value)
                    };
                    assert_eq!(completion(context, Some(value)), expected, "{context:?} {value:?}");
                }
            }
        }
    }

    /// Claim: A submitted uncertain COMMIT stays unknown for every cause, while Failed follows the table.
    /// ´claim:host:store-error-commit-map´
    /// ´test:unit:store-error-commit-map´
    #[test]
    fn store_error_commit_map() {
        for cause in CAUSES {
            assert_eq!(
                completion(RequestContext::Commit, Some(ServerError::Uncertain(cause))),
                StorageError::CommitUnknown
            );
            let expected = if cause == Cause::ConstraintViolation {
                StorageError::CorruptHistory
            } else {
                StorageError::Server(ServerError::Failed(cause))
            };
            assert_eq!(completion(RequestContext::Commit, Some(ServerError::Failed(cause))), expected);
        }
    }

    /// Claim: An unanswered submitted failure is Transport outside COMMIT and `CommitUnknown` at COMMIT.
    /// ´claim:host:store-error-no-answer´
    /// ´test:unit:store-error-no-answer´
    #[test]
    fn store_error_no_answer() {
        for context in [RequestContext::Writer, RequestContext::Other] {
            assert_eq!(completion(context, None), StorageError::Transport);
        }
        assert_eq!(completion(RequestContext::Commit, None), StorageError::CommitUnknown);
    }

    /// Claim: An acknowledged COMMIT remains successful and leaves a later answer for the next pre-request take.
    /// ´claim:host:store-error-acknowledged-success´
    /// ´test:unit:store-error-acknowledged-success´
    #[test]
    fn store_error_acknowledged_success() {
        run(async {
            let state = state();
            let answer = state.answer.clone();
            assert_eq!(
                state
                    .request(RequestContext::Commit, async move {
                        *answer.lock().unwrap() = Some(ServerError::Uncertain(Cause::Terminated));
                        Ok::<_, ()>(7)
                    })
                    .await,
                Ok(7)
            );
            assert!(!state.retired());
            assert_eq!(
                state.request(RequestContext::Other, async { Ok::<_, ()>(8) }).await,
                Err(StorageError::Transport)
            );
            assert!(state.retired());
        });
    }

    /// Claim: Dropping a polled pending request retires before a later request can submit.
    /// ´claim:host:store-error-abandoned-request´
    /// ´test:unit:store-error-abandoned-request´
    #[test]
    fn store_error_abandoned_request() {
        run(async {
            let state = state();
            let (started, seen) = tokio::sync::oneshot::channel();
            let active = state.clone();
            let task = tokio::spawn(async move {
                active
                    .request(RequestContext::Other, async move {
                        let _ = started.send(());
                        std::future::pending::<Result<(), ()>>().await
                    })
                    .await
            });
            seen.await.unwrap();
            task.abort();
            drop(task.await);
            assert!(state.retired());
            assert_eq!(
                state.request(RequestContext::Other, async { Ok::<_, ()>(()) }).await,
                Err(StorageError::Transport)
            );
            assert_eq!(
                state
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|value| **value == "submit")
                    .count(),
                1
            );
        });
    }

    /// Claim: Successful wrapped rollback keeps seven store-decided refusals and allows the next transaction.
    /// ´claim:host:store-error-local-refusal-rollback´
    /// ´test:unit:store-error-local-refusal-rollback´
    #[test]
    fn store_error_local_refusal_rollback() {
        run(async {
            for primary in [
                StorageError::EditionConflict,
                StorageError::Gap,
                StorageError::Overlap,
                StorageError::Predecessor,
                StorageError::Retroactive,
                StorageError::Injected,
                StorageError::CorruptHistory,
            ] {
                let state = state();
                let (returned, succeeded) = state.cleanup(primary, async { Ok::<(), ()>(()) }).await;
                assert_eq!(returned, primary);
                assert!(succeeded);
                assert_eq!(state.request(RequestContext::Other, async { Ok::<_, ()>(()) }).await, Ok(()));
                assert!(!state.retired());
                assert_eq!(
                    state
                        .events
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|value| **value == "submit")
                        .count(),
                    2
                );
            }
        });
    }

    /// Claim: Scripted COMMIT and cleanup preserve reuse, while an unended transaction Drop retires before reuse.
    /// ´claim:host:store-error-snapshot-end´
    /// ´test:unit:store-error-snapshot-end´
    #[test]
    fn store_error_snapshot_end() {
        run(async {
            let success = state();
            assert_eq!(
                success.request(RequestContext::Commit, async { Ok::<(), ()>(()) }).await,
                Ok(())
            );
            assert_eq!(
                success.request(RequestContext::Other, async { Ok::<(), ()>(()) }).await,
                Ok(())
            );
            let refused = state();
            let (primary, ended) = refused.cleanup(StorageError::ReadLimit, async { Ok::<(), ()>(()) }).await;
            assert_eq!(primary, StorageError::ReadLimit);
            assert!(ended);
            assert_eq!(
                refused.request(RequestContext::Other, async { Ok::<(), ()>(()) }).await,
                Ok(())
            );
            let unended = state();
            drop(StatementTransaction {
                raw: None,
                state: unended.clone(),
                ended: false,
                context: RequestContext::Other,
            });
            assert_eq!(
                unended.request(RequestContext::Other, async { Ok::<(), ()>(()) }).await,
                Err(StorageError::Transport)
            );
        });
    }
}
