//! Closed effective-history storage; no executable opens this library surface.
//! (´def:host:effective-storage´)
use crate::{Session, storage_payload as encoding};
use pn_interchange::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
    Transport,
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
fn digest(recipe: &str, bytes: &[u8]) -> [u8; 32] {
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
    fn encoded(family: Family, value: Value, disclosure: Option<[u8; 32]>) -> Result<Self, StorageError> {
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

/// No epoch result is admitted by bite 2; bite 5 supplies the ledger/result carrier.
/// The eventual transaction exposes input references, debit evidence and result
/// together or none, with structural-event idempotence before retrying debits.
/// (´open:host:admitted-epoch-result´)
#[derive(Debug)]
pub enum AdmittedEpoch {}

type History = BTreeMap<(Family, String), Vec<EffectiveRow>>;
fn check(version: &Version) -> Result<(), StorageError> {
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
        let result = classified(append(&mut next, version, predecessor));
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
#[derive(Clone, Copy)]
enum Statement {
    BootstrapLock,
    HasTables,
    HasIdentity,
    Create,
    SetIdentity,
    GetIdentity,
    EnsureIndexes,
    LockHistory,
    ReadHistory,
    ReadKey,
    ReadBoundary,
    Close,
    Insert,
}
impl Statement {
    const fn sql(self) -> &'static str {
        match self {
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
    async fn transaction(&mut self) -> Result<StatementTransaction<'_>, tokio_postgres::Error> {
        Ok(StatementTransaction(self.raw.transaction().await?))
    }
    async fn snapshot(&mut self) -> Result<StatementTransaction<'_>, tokio_postgres::Error> {
        Ok(StatementTransaction(
            self.raw
                .build_transaction()
                .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await?,
        ))
    }
}
struct StatementTransaction<'a>(tokio_postgres::Transaction<'a>);
impl StatementTransaction<'_> {
    async fn query(
        &self,
        statement: Statement,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<tokio_postgres::Row>, tokio_postgres::Error> {
        self.0.query(statement.sql(), params).await
    }
    async fn query_one(
        &self,
        statement: Statement,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<tokio_postgres::Row, tokio_postgres::Error> {
        self.0.query_one(statement.sql(), params).await
    }
    async fn execute(
        &self,
        statement: Statement,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<u64, tokio_postgres::Error> {
        self.0.execute(statement.sql(), params).await
    }
    async fn batch_execute(&self, statement: Statement) -> Result<(), tokio_postgres::Error> {
        self.0.batch_execute(statement.sql()).await
    }
    async fn commit(self) -> Result<(), tokio_postgres::Error> {
        self.0.commit().await
    }
    async fn rollback(self) -> Result<(), tokio_postgres::Error> {
        self.0.rollback().await
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
    /// Refuses foreign schema identity or transport failure; only the declared indexes are added idempotently.
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
        let transaction = session.client.transaction().await.map_err(|_| StorageError::Transport)?;
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
        transaction.commit().await.map_err(|_| StorageError::CommitUnknown)?;
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
        let transaction = self.session.client.snapshot().await.map_err(|_| StorageError::Transport)?;
        let at_sql = i64::try_from(at).unwrap_or(i64::MAX);
        let history = read(&transaction, Statement::ReadBoundary, &[&at_sql], false).await?;
        let result = boundary(&history, at, required);
        transaction.commit().await.map_err(|_| StorageError::Transport)?;
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
        let transaction = self.session.client.snapshot().await.map_err(|_| StorageError::Transport)?;
        let result = read(&transaction, Statement::ReadHistory, &[], true).await.map(|_| ());
        transaction.commit().await.map_err(|_| StorageError::Transport)?;
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
        let transaction = self.session.client.transaction().await.map_err(|_| StorageError::Transport)?;
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
            transaction.rollback().await.map_err(|_| StorageError::Transport)?;
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
        transaction.commit().await.map_err(|_| StorageError::CommitUnknown)?;
        meter.commit();
        Ok(true)
    }
}
async fn observed<T>(future: impl std::future::Future<Output = Result<T, tokio_postgres::Error>>) -> Result<T, StorageError> {
    metrics::counter!("host__root__sig__design__storage__queries").increment(1);
    let started = std::time::Instant::now();
    let result = future.await.map_err(|_| StorageError::Transport);
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
