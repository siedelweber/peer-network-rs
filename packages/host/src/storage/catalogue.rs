//! Exact tree catalogue creation and verification, without result writes.
//! (´[ROOT-amend:storage:admitted-layout]´)
use super::{Session, Statement, StorageError, TransactionMeter, classified, observed};

#[cfg(test)]
mod tests;

const IDENTITY: &str = "pn-host/effective-history/v2";

/// Create the exact tree catalogue only in an empty database, or verify it without repair.
/// This returns no result-transaction capability and leaves the protected session with its caller.
/// (´[ROOT-amend:storage:admitted-layout]´)
/// # Errors
/// Refuses another schema identity, any catalogue mismatch or a transport failure.
#[tracing::instrument(
    name = "sig:design:storage",
    fields(
        execution_owner = "HOST",
        claim_owner = "ROOT",
        claim_label = "sig:design:storage",
        source_item = "storage::catalogue::open",
        asynchronous = true
    ),
    ret
)]
pub async fn open(session: &mut Session) -> Result<(), StorageError> {
    classified(open_inner(session).await)
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
        observed(transaction.batch_execute(Statement::EnsureIndexes)).await?;
        observed(transaction.batch_execute(Statement::CreateEpochStore)).await?;
        observed(transaction.execute(Statement::SetIdentity, &[&IDENTITY])).await?;
    }
    let rows = observed(transaction.query(Statement::GetIdentity, &[])).await?;
    if rows.len() != 1 || rows[0].get::<_, String>(0) != IDENTITY {
        return Err(StorageError::SchemaIdentity);
    }
    let history: bool = observed(transaction.query_one(Statement::VerifyIndexes, &[])).await?.get(0);
    let catalogue: bool = observed(transaction.query_one(Statement::VerifyEpochStore, &[]))
        .await?
        .get(0);
    if !history || !catalogue {
        return Err(StorageError::IndexDefinition);
    }
    transaction.commit().await.map_err(|_| StorageError::CommitUnknown)?;
    meter.commit();
    Ok(())
}

// The pinned service's deparser supplies the catalogue spelling; every expected
// member is compared as a complete multiset, including catalogued not-null rows.
pub(super) const CREATE: &str = r#"
CREATE TABLE public.pn_admission_generations (
 scope text COLLATE "C" NOT NULL,
 generation bigint NOT NULL,
 label text COLLATE "C" NOT NULL,
 previous bigint,
 minimum bigint NOT NULL,
 version_count bigint NOT NULL,
 closure_count bigint NOT NULL,
 PRIMARY KEY (scope,generation),
 UNIQUE (scope,label),
 CHECK (octet_length(scope) BETWEEN 1 AND 1024),
 CHECK (octet_length(label) BETWEEN 1 AND 1024),
 CHECK (generation > 0),
 CHECK (minimum BETWEEN 1 AND generation),
 CHECK (version_count >= 0),
 CHECK (closure_count >= 0),
 CHECK ((generation = 1 AND previous IS NULL AND minimum = 1) OR (generation > 1 AND previous = generation - 1 AND previous IS NOT NULL))
);
CREATE TABLE public.pn_admission_versions (
 scope text COLLATE "C" NOT NULL,
 generation bigint NOT NULL,
 family text COLLATE "C" NOT NULL,
 key text COLLATE "C" NOT NULL,
 edition text COLLATE "C" NOT NULL,
 PRIMARY KEY (family,key,edition),
 CHECK (octet_length(key) BETWEEN 1 AND 1024),
 CHECK (octet_length(edition) BETWEEN 1 AND 1024),
 CHECK (family IN ('rule','constants'))
);
CREATE TABLE public.pn_admission_closures (
 scope text COLLATE "C" NOT NULL,
 generation bigint NOT NULL,
 family text COLLATE "C" NOT NULL,
 key text COLLATE "C" NOT NULL,
 edition text COLLATE "C" NOT NULL,
 PRIMARY KEY (family,key,edition),
 CHECK (octet_length(key) BETWEEN 1 AND 1024),
 CHECK (octet_length(edition) BETWEEN 1 AND 1024),
 CHECK (family IN ('rule','constants'))
);
CREATE TABLE public.pn_epoch_scopes (
 scope text COLLATE "C" NOT NULL,
 context_root bytea NOT NULL,
 PRIMARY KEY (scope),
 CHECK (octet_length(scope) BETWEEN 1 AND 1024),
 CHECK (octet_length(context_root) = 32)
);
CREATE TABLE public.pn_epoch_branches (
 scope text COLLATE "C" NOT NULL,
 segment bytea NOT NULL,
 start_depth bigint NOT NULL,
 parent_segment bytea,
 fork_parent bytea,
 fork_depth bigint NOT NULL,
 PRIMARY KEY (scope,segment),
 CHECK (octet_length(segment) = 32),
 CHECK (octet_length(parent_segment) = 32),
 CHECK (octet_length(fork_parent) = 32),
 CHECK (start_depth > 0),
 CHECK (fork_depth >= 0),
 CHECK ((parent_segment IS NULL AND fork_parent IS NULL AND start_depth = 1 AND fork_depth = 0) OR (parent_segment IS NOT NULL AND fork_parent IS NOT NULL AND start_depth = fork_depth + 1))
);
CREATE TABLE public.pn_epoch_results (
 scope text COLLATE "C" NOT NULL,
 identity bytea NOT NULL,
 depth bigint NOT NULL,
 parent bytea,
 parent_depth bigint,
 parent_segment bytea,
 segment bytea NOT NULL,
 generation bigint NOT NULL,
 package_bytes bigint NOT NULL,
 package_chunks bigint NOT NULL,
 reference_count bigint NOT NULL,
 debit_count bigint NOT NULL,
 PRIMARY KEY (scope,identity),
 UNIQUE (scope,identity,depth),
 UNIQUE (scope,identity,segment,depth),
 UNIQUE (scope,identity,parent,parent_segment,parent_depth),
 CHECK (depth > 0),
 CHECK (package_bytes > 0),
 CHECK (package_chunks > 0),
 CHECK (reference_count >= 0),
 CHECK (debit_count >= 0),
 CHECK (octet_length(identity) = 32),
 CHECK (octet_length(segment) = 32),
 CHECK (octet_length(parent) = 32),
 CHECK (octet_length(parent_segment) = 32),
 CHECK ((depth = 1 AND parent IS NULL AND parent_depth IS NULL AND parent_segment IS NULL) OR (depth > 1 AND parent IS NOT NULL AND parent_depth IS NOT NULL AND parent_segment IS NOT NULL AND parent_depth = depth - 1)),
 CHECK (identity = segment OR parent_segment = segment),
 CHECK (depth <> 1 OR identity = segment),
 UNIQUE (scope,segment,depth)
);
CREATE TABLE public.pn_epoch_package_chunks (
 scope text COLLATE "C" NOT NULL,
 identity bytea NOT NULL,
 ordinal bigint NOT NULL,
 bytes bytea NOT NULL,
 PRIMARY KEY (scope,identity,ordinal),
 CHECK (ordinal >= 0),
 CHECK (octet_length(bytes) BETWEEN 1 AND 262144)
);
CREATE TABLE public.pn_epoch_references (
 scope text COLLATE "C" NOT NULL,
 identity bytea NOT NULL,
 selected_at bigint NOT NULL,
 family text COLLATE "C" NOT NULL,
 key text COLLATE "C" NOT NULL,
 edition text COLLATE "C" NOT NULL,
 judgement_origin bytea NOT NULL,
 PRIMARY KEY (scope,identity,selected_at,family,key),
 CHECK (selected_at >= 0),
 CHECK (octet_length(key) BETWEEN 1 AND 1024),
 CHECK (octet_length(edition) BETWEEN 1 AND 1024),
 CHECK (family IN ('constants','rule','marker-policy','lineage','burn-publication','unsettled-recognition'))
);
CREATE TABLE public.pn_epoch_debits (
 scope text COLLATE "C" NOT NULL,
 origin bytea NOT NULL,
 author text COLLATE "C" NOT NULL,
 act_sequence text COLLATE "C" NOT NULL,
 act_family text COLLATE "C" NOT NULL,
 writing_boundary bigint NOT NULL,
 vintage_bytes bigint NOT NULL,
 vintage_chunks bigint NOT NULL,
 PRIMARY KEY (scope,origin,author,act_sequence,act_family),
 CHECK (octet_length(origin) = 32),
 CHECK (octet_length(scope) + octet_length(author) + length(octet_length(author)::text) + 1 + octet_length(act_sequence) + length(octet_length(act_sequence)::text) + 1 + octet_length(act_family) + length(octet_length(act_family)::text) + 1 <= 1024),
 CHECK (act_sequence ~ '^(0|[1-9][0-9]*)$' AND length(act_sequence) <= 20 AND (length(act_sequence) < 20 OR act_sequence <= '18446744073709551615')),
 CHECK (writing_boundary > 0),
 CHECK (vintage_bytes > 0),
 CHECK (vintage_chunks > 0)
);
CREATE TABLE public.pn_epoch_debit_chunks (
 scope text COLLATE "C" NOT NULL,
 origin bytea NOT NULL,
 author text COLLATE "C" NOT NULL,
 act_sequence text COLLATE "C" NOT NULL,
 act_family text COLLATE "C" NOT NULL,
 ordinal bigint NOT NULL,
 bytes bytea NOT NULL,
 PRIMARY KEY (scope,origin,author,act_sequence,act_family,ordinal),
 CHECK (ordinal >= 0),
 CHECK (octet_length(bytes) BETWEEN 1 AND 262144)
);
CREATE TABLE public.pn_epoch_result_debits (
 scope text COLLATE "C" NOT NULL,
 origin bytea NOT NULL,
 segment bytea NOT NULL,
 origin_depth bigint NOT NULL,
 author text COLLATE "C" NOT NULL,
 act_sequence text COLLATE "C" NOT NULL,
 act_family text COLLATE "C" NOT NULL,
 PRIMARY KEY (scope,origin,author,act_sequence,act_family),
 CHECK (origin_depth > 0),
 CHECK (octet_length(origin) = 32),
 CHECK (octet_length(segment) = 32)
);
ALTER TABLE public.pn_admission_generations ADD FOREIGN KEY (scope,previous) REFERENCES public.pn_admission_generations(scope,generation);
ALTER TABLE public.pn_admission_generations ADD FOREIGN KEY (scope,minimum) REFERENCES public.pn_admission_generations(scope,generation);
ALTER TABLE public.pn_admission_versions ADD FOREIGN KEY (family,key,edition) REFERENCES public.pn_versions(family,key,edition);
ALTER TABLE public.pn_admission_versions ADD FOREIGN KEY (scope,generation) REFERENCES public.pn_admission_generations(scope,generation);
ALTER TABLE public.pn_admission_closures ADD FOREIGN KEY (family,key,edition) REFERENCES public.pn_closures(family,key,edition);
ALTER TABLE public.pn_admission_closures ADD FOREIGN KEY (scope,generation) REFERENCES public.pn_admission_generations(scope,generation);
ALTER TABLE public.pn_epoch_scopes ADD FOREIGN KEY (scope,context_root) REFERENCES public.pn_epoch_results(scope,identity) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE public.pn_epoch_branches ADD FOREIGN KEY (scope) REFERENCES public.pn_epoch_scopes(scope);
ALTER TABLE public.pn_epoch_branches ADD FOREIGN KEY (scope,segment,start_depth) REFERENCES public.pn_epoch_results(scope,identity,depth) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE public.pn_epoch_branches ADD FOREIGN KEY (scope,segment,fork_parent,parent_segment,fork_depth) REFERENCES public.pn_epoch_results(scope,identity,parent,parent_segment,parent_depth) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE public.pn_epoch_branches ADD FOREIGN KEY (scope,parent_segment) REFERENCES public.pn_epoch_branches(scope,segment);
ALTER TABLE public.pn_epoch_branches ADD FOREIGN KEY (scope,fork_parent,parent_segment,fork_depth) REFERENCES public.pn_epoch_results(scope,identity,segment,depth);
ALTER TABLE public.pn_epoch_results ADD FOREIGN KEY (scope) REFERENCES public.pn_epoch_scopes(scope);
ALTER TABLE public.pn_epoch_results ADD FOREIGN KEY (scope,generation) REFERENCES public.pn_admission_generations(scope,generation);
ALTER TABLE public.pn_epoch_results ADD FOREIGN KEY (scope,segment) REFERENCES public.pn_epoch_branches(scope,segment);
ALTER TABLE public.pn_epoch_results ADD FOREIGN KEY (scope,parent,parent_segment,parent_depth) REFERENCES public.pn_epoch_results(scope,identity,segment,depth);
ALTER TABLE public.pn_epoch_package_chunks ADD FOREIGN KEY (scope,identity) REFERENCES public.pn_epoch_results(scope,identity);
ALTER TABLE public.pn_epoch_references ADD FOREIGN KEY (scope,identity) REFERENCES public.pn_epoch_results(scope,identity);
ALTER TABLE public.pn_epoch_references ADD FOREIGN KEY (family,key,edition) REFERENCES public.pn_versions(family,key,edition);
ALTER TABLE public.pn_epoch_references ADD FOREIGN KEY (scope,judgement_origin) REFERENCES public.pn_epoch_results(scope,identity);
ALTER TABLE public.pn_epoch_debits ADD FOREIGN KEY (scope,origin) REFERENCES public.pn_epoch_results(scope,identity);
ALTER TABLE public.pn_epoch_debit_chunks ADD FOREIGN KEY (scope,origin,author,act_sequence,act_family) REFERENCES public.pn_epoch_debits(scope,origin,author,act_sequence,act_family);
ALTER TABLE public.pn_epoch_result_debits ADD FOREIGN KEY (scope,origin,author,act_sequence,act_family) REFERENCES public.pn_epoch_debits(scope,origin,author,act_sequence,act_family);
ALTER TABLE public.pn_epoch_result_debits ADD FOREIGN KEY (scope,origin,segment,origin_depth) REFERENCES public.pn_epoch_results(scope,identity,segment,depth);
CREATE INDEX pn_admission_versions_generation ON public.pn_admission_versions(scope,generation,family,key);
CREATE INDEX pn_admission_closures_generation ON public.pn_admission_closures(scope,generation,family,key);
CREATE INDEX pn_epoch_results_children ON public.pn_epoch_results(scope,parent,identity);
CREATE INDEX pn_epoch_result_debits_path ON public.pn_epoch_result_debits(scope,segment,origin_depth,author,act_sequence,act_family);
"#;

pub(super) const VERIFY: &str = r"
WITH expected_columns(relation,name,ordinal,kind,required,collation_name) AS (VALUES
 ('pn_admission_generations','scope','1','text','true','C'),
 ('pn_admission_generations','generation','2','bigint','true',''),
 ('pn_admission_generations','label','3','text','true','C'),
 ('pn_admission_generations','previous','4','bigint','false',''),
 ('pn_admission_generations','minimum','5','bigint','true',''),
 ('pn_admission_generations','version_count','6','bigint','true',''),
 ('pn_admission_generations','closure_count','7','bigint','true',''),
 ('pn_admission_versions','scope','1','text','true','C'),
 ('pn_admission_versions','generation','2','bigint','true',''),
 ('pn_admission_versions','family','3','text','true','C'),
 ('pn_admission_versions','key','4','text','true','C'),
 ('pn_admission_versions','edition','5','text','true','C'),
 ('pn_admission_closures','scope','1','text','true','C'),
 ('pn_admission_closures','generation','2','bigint','true',''),
 ('pn_admission_closures','family','3','text','true','C'),
 ('pn_admission_closures','key','4','text','true','C'),
 ('pn_admission_closures','edition','5','text','true','C'),
 ('pn_epoch_scopes','scope','1','text','true','C'),
 ('pn_epoch_scopes','context_root','2','bytea','true',''),
 ('pn_epoch_branches','scope','1','text','true','C'),
 ('pn_epoch_branches','segment','2','bytea','true',''),
 ('pn_epoch_branches','start_depth','3','bigint','true',''),
 ('pn_epoch_branches','parent_segment','4','bytea','false',''),
 ('pn_epoch_branches','fork_parent','5','bytea','false',''),
 ('pn_epoch_branches','fork_depth','6','bigint','true',''),
 ('pn_epoch_results','scope','1','text','true','C'),
 ('pn_epoch_results','identity','2','bytea','true',''),
 ('pn_epoch_results','depth','3','bigint','true',''),
 ('pn_epoch_results','parent','4','bytea','false',''),
 ('pn_epoch_results','parent_depth','5','bigint','false',''),
 ('pn_epoch_results','parent_segment','6','bytea','false',''),
 ('pn_epoch_results','segment','7','bytea','true',''),
 ('pn_epoch_results','generation','8','bigint','true',''),
 ('pn_epoch_results','package_bytes','9','bigint','true',''),
 ('pn_epoch_results','package_chunks','10','bigint','true',''),
 ('pn_epoch_results','reference_count','11','bigint','true',''),
 ('pn_epoch_results','debit_count','12','bigint','true',''),
 ('pn_epoch_package_chunks','scope','1','text','true','C'),
 ('pn_epoch_package_chunks','identity','2','bytea','true',''),
 ('pn_epoch_package_chunks','ordinal','3','bigint','true',''),
 ('pn_epoch_package_chunks','bytes','4','bytea','true',''),
 ('pn_epoch_references','scope','1','text','true','C'),
 ('pn_epoch_references','identity','2','bytea','true',''),
 ('pn_epoch_references','selected_at','3','bigint','true',''),
 ('pn_epoch_references','family','4','text','true','C'),
 ('pn_epoch_references','key','5','text','true','C'),
 ('pn_epoch_references','edition','6','text','true','C'),
 ('pn_epoch_references','judgement_origin','7','bytea','true',''),
 ('pn_epoch_debits','scope','1','text','true','C'),
 ('pn_epoch_debits','origin','2','bytea','true',''),
 ('pn_epoch_debits','author','3','text','true','C'),
 ('pn_epoch_debits','act_sequence','4','text','true','C'),
 ('pn_epoch_debits','act_family','5','text','true','C'),
 ('pn_epoch_debits','writing_boundary','6','bigint','true',''),
 ('pn_epoch_debits','vintage_bytes','7','bigint','true',''),
 ('pn_epoch_debits','vintage_chunks','8','bigint','true',''),
 ('pn_epoch_debit_chunks','scope','1','text','true','C'),
 ('pn_epoch_debit_chunks','origin','2','bytea','true',''),
 ('pn_epoch_debit_chunks','author','3','text','true','C'),
 ('pn_epoch_debit_chunks','act_sequence','4','text','true','C'),
 ('pn_epoch_debit_chunks','act_family','5','text','true','C'),
 ('pn_epoch_debit_chunks','ordinal','6','bigint','true',''),
 ('pn_epoch_debit_chunks','bytes','7','bytea','true',''),
 ('pn_epoch_result_debits','scope','1','text','true','C'),
 ('pn_epoch_result_debits','origin','2','bytea','true',''),
 ('pn_epoch_result_debits','segment','3','bytea','true',''),
 ('pn_epoch_result_debits','origin_depth','4','bigint','true',''),
 ('pn_epoch_result_debits','author','5','text','true','C'),
 ('pn_epoch_result_debits','act_sequence','6','text','true','C'),
 ('pn_epoch_result_debits','act_family','7','text','true','C')
), actual_columns AS (
 SELECT c.relname::text,a.attname::text,a.attnum::text,format_type(a.atttypid,a.atttypmod),a.attnotnull::text,COALESCE(co.collname::text,'')
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
 LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
 WHERE c.relnamespace='public'::regnamespace AND c.relkind='r'
 AND c.relname IN (SELECT relation FROM expected_columns) AND a.attnum>0 AND NOT a.attisdropped
), expected_constraints(relation,definition,kind,deferred_capable,deferred) AS (VALUES
 ('pn_admission_closures','CHECK (((octet_length(edition) >= 1) AND (octet_length(edition) <= 1024)))','c','false','false'),
 ('pn_admission_closures','NOT NULL edition','n','false','false'),
 ('pn_admission_closures','CHECK ((family = ANY (ARRAY[''rule''::text, ''constants''::text])))','c','false','false'),
 ('pn_admission_closures','FOREIGN KEY (family, key, edition) REFERENCES pn_closures(family, key, edition)','f','false','false'),
 ('pn_admission_closures','NOT NULL family','n','false','false'),
 ('pn_admission_closures','NOT NULL generation','n','false','false'),
 ('pn_admission_closures','CHECK (((octet_length(key) >= 1) AND (octet_length(key) <= 1024)))','c','false','false'),
 ('pn_admission_closures','NOT NULL key','n','false','false'),
 ('pn_admission_closures','PRIMARY KEY (family, key, edition)','p','false','false'),
 ('pn_admission_closures','FOREIGN KEY (scope, generation) REFERENCES pn_admission_generations(scope, generation)','f','false','false'),
 ('pn_admission_closures','NOT NULL scope','n','false','false'),
 ('pn_admission_generations','CHECK (((minimum >= 1) AND (minimum <= generation)))','c','false','false'),
 ('pn_admission_generations','CHECK ((((generation = 1) AND (previous IS NULL) AND (minimum = 1)) OR ((generation > 1) AND (previous = (generation - 1)) AND (previous IS NOT NULL))))','c','false','false'),
 ('pn_admission_generations','CHECK ((closure_count >= 0))','c','false','false'),
 ('pn_admission_generations','NOT NULL closure_count','n','false','false'),
 ('pn_admission_generations','CHECK ((generation > 0))','c','false','false'),
 ('pn_admission_generations','NOT NULL generation','n','false','false'),
 ('pn_admission_generations','CHECK (((octet_length(label) >= 1) AND (octet_length(label) <= 1024)))','c','false','false'),
 ('pn_admission_generations','NOT NULL label','n','false','false'),
 ('pn_admission_generations','NOT NULL minimum','n','false','false'),
 ('pn_admission_generations','PRIMARY KEY (scope, generation)','p','false','false'),
 ('pn_admission_generations','CHECK (((octet_length(scope) >= 1) AND (octet_length(scope) <= 1024)))','c','false','false'),
 ('pn_admission_generations','UNIQUE (scope, label)','u','false','false'),
 ('pn_admission_generations','FOREIGN KEY (scope, minimum) REFERENCES pn_admission_generations(scope, generation)','f','false','false'),
 ('pn_admission_generations','NOT NULL scope','n','false','false'),
 ('pn_admission_generations','FOREIGN KEY (scope, previous) REFERENCES pn_admission_generations(scope, generation)','f','false','false'),
 ('pn_admission_generations','CHECK ((version_count >= 0))','c','false','false'),
 ('pn_admission_generations','NOT NULL version_count','n','false','false'),
 ('pn_admission_versions','CHECK (((octet_length(edition) >= 1) AND (octet_length(edition) <= 1024)))','c','false','false'),
 ('pn_admission_versions','NOT NULL edition','n','false','false'),
 ('pn_admission_versions','CHECK ((family = ANY (ARRAY[''rule''::text, ''constants''::text])))','c','false','false'),
 ('pn_admission_versions','FOREIGN KEY (family, key, edition) REFERENCES pn_versions(family, key, edition)','f','false','false'),
 ('pn_admission_versions','NOT NULL family','n','false','false'),
 ('pn_admission_versions','NOT NULL generation','n','false','false'),
 ('pn_admission_versions','CHECK (((octet_length(key) >= 1) AND (octet_length(key) <= 1024)))','c','false','false'),
 ('pn_admission_versions','NOT NULL key','n','false','false'),
 ('pn_admission_versions','PRIMARY KEY (family, key, edition)','p','false','false'),
 ('pn_admission_versions','FOREIGN KEY (scope, generation) REFERENCES pn_admission_generations(scope, generation)','f','false','false'),
 ('pn_admission_versions','NOT NULL scope','n','false','false'),
 ('pn_epoch_branches','CHECK ((((parent_segment IS NULL) AND (fork_parent IS NULL) AND (start_depth = 1) AND (fork_depth = 0)) OR ((parent_segment IS NOT NULL) AND (fork_parent IS NOT NULL) AND (start_depth = (fork_depth + 1)))))','c','false','false'),
 ('pn_epoch_branches','CHECK ((fork_depth >= 0))','c','false','false'),
 ('pn_epoch_branches','NOT NULL fork_depth','n','false','false'),
 ('pn_epoch_branches','CHECK ((octet_length(fork_parent) = 32))','c','false','false'),
 ('pn_epoch_branches','CHECK ((octet_length(parent_segment) = 32))','c','false','false'),
 ('pn_epoch_branches','PRIMARY KEY (scope, segment)','p','false','false'),
 ('pn_epoch_branches','FOREIGN KEY (scope) REFERENCES pn_epoch_scopes(scope)','f','false','false'),
 ('pn_epoch_branches','FOREIGN KEY (scope, fork_parent, parent_segment, fork_depth) REFERENCES pn_epoch_results(scope, identity, segment, depth)','f','false','false'),
 ('pn_epoch_branches','NOT NULL scope','n','false','false'),
 ('pn_epoch_branches','FOREIGN KEY (scope, parent_segment) REFERENCES pn_epoch_branches(scope, segment)','f','false','false'),
 ('pn_epoch_branches','FOREIGN KEY (scope, segment, fork_parent, parent_segment, fork_depth) REFERENCES pn_epoch_results(scope, identity, parent, parent_segment, parent_depth) DEFERRABLE INITIALLY DEFERRED','f','true','true'),
 ('pn_epoch_branches','FOREIGN KEY (scope, segment, start_depth) REFERENCES pn_epoch_results(scope, identity, depth) DEFERRABLE INITIALLY DEFERRED','f','true','true'),
 ('pn_epoch_branches','CHECK ((octet_length(segment) = 32))','c','false','false'),
 ('pn_epoch_branches','NOT NULL segment','n','false','false'),
 ('pn_epoch_branches','CHECK ((start_depth > 0))','c','false','false'),
 ('pn_epoch_branches','NOT NULL start_depth','n','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL act_family','n','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL act_sequence','n','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL author','n','false','false'),
 ('pn_epoch_debit_chunks','CHECK (((octet_length(bytes) >= 1) AND (octet_length(bytes) <= 262144)))','c','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL bytes','n','false','false'),
 ('pn_epoch_debit_chunks','CHECK ((ordinal >= 0))','c','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL ordinal','n','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL origin','n','false','false'),
 ('pn_epoch_debit_chunks','PRIMARY KEY (scope, origin, author, act_sequence, act_family, ordinal)','p','false','false'),
 ('pn_epoch_debit_chunks','NOT NULL scope','n','false','false'),
 ('pn_epoch_debit_chunks','FOREIGN KEY (scope, origin, author, act_sequence, act_family) REFERENCES pn_epoch_debits(scope, origin, author, act_sequence, act_family)','f','false','false'),
 ('pn_epoch_debits','NOT NULL act_family','n','false','false'),
 ('pn_epoch_debits','CHECK (((act_sequence ~ ''^(0|[1-9][0-9]*)$''::text) AND (length(act_sequence) <= 20) AND ((length(act_sequence) < 20) OR (act_sequence <= ''18446744073709551615''::text))))','c','false','false'),
 ('pn_epoch_debits','NOT NULL act_sequence','n','false','false'),
 ('pn_epoch_debits','NOT NULL author','n','false','false'),
 ('pn_epoch_debits','CHECK (((((((((((octet_length(scope) + octet_length(author)) + length((octet_length(author))::text)) + 1) + octet_length(act_sequence)) + length((octet_length(act_sequence))::text)) + 1) + octet_length(act_family)) + length((octet_length(act_family))::text)) + 1) <= 1024))','c','false','false'),
 ('pn_epoch_debits','CHECK ((octet_length(origin) = 32))','c','false','false'),
 ('pn_epoch_debits','NOT NULL origin','n','false','false'),
 ('pn_epoch_debits','PRIMARY KEY (scope, origin, author, act_sequence, act_family)','p','false','false'),
 ('pn_epoch_debits','NOT NULL scope','n','false','false'),
 ('pn_epoch_debits','FOREIGN KEY (scope, origin) REFERENCES pn_epoch_results(scope, identity)','f','false','false'),
 ('pn_epoch_debits','CHECK ((vintage_bytes > 0))','c','false','false'),
 ('pn_epoch_debits','NOT NULL vintage_bytes','n','false','false'),
 ('pn_epoch_debits','CHECK ((vintage_chunks > 0))','c','false','false'),
 ('pn_epoch_debits','NOT NULL vintage_chunks','n','false','false'),
 ('pn_epoch_debits','CHECK ((writing_boundary > 0))','c','false','false'),
 ('pn_epoch_debits','NOT NULL writing_boundary','n','false','false'),
 ('pn_epoch_package_chunks','CHECK (((octet_length(bytes) >= 1) AND (octet_length(bytes) <= 262144)))','c','false','false'),
 ('pn_epoch_package_chunks','NOT NULL bytes','n','false','false'),
 ('pn_epoch_package_chunks','NOT NULL identity','n','false','false'),
 ('pn_epoch_package_chunks','CHECK ((ordinal >= 0))','c','false','false'),
 ('pn_epoch_package_chunks','NOT NULL ordinal','n','false','false'),
 ('pn_epoch_package_chunks','PRIMARY KEY (scope, identity, ordinal)','p','false','false'),
 ('pn_epoch_package_chunks','FOREIGN KEY (scope, identity) REFERENCES pn_epoch_results(scope, identity)','f','false','false'),
 ('pn_epoch_package_chunks','NOT NULL scope','n','false','false'),
 ('pn_epoch_references','CHECK (((octet_length(edition) >= 1) AND (octet_length(edition) <= 1024)))','c','false','false'),
 ('pn_epoch_references','NOT NULL edition','n','false','false'),
 ('pn_epoch_references','CHECK ((family = ANY (ARRAY[''constants''::text, ''rule''::text, ''marker-policy''::text, ''lineage''::text, ''burn-publication''::text, ''unsettled-recognition''::text])))','c','false','false'),
 ('pn_epoch_references','FOREIGN KEY (family, key, edition) REFERENCES pn_versions(family, key, edition)','f','false','false'),
 ('pn_epoch_references','NOT NULL family','n','false','false'),
 ('pn_epoch_references','NOT NULL identity','n','false','false'),
 ('pn_epoch_references','NOT NULL judgement_origin','n','false','false'),
 ('pn_epoch_references','CHECK (((octet_length(key) >= 1) AND (octet_length(key) <= 1024)))','c','false','false'),
 ('pn_epoch_references','NOT NULL key','n','false','false'),
 ('pn_epoch_references','PRIMARY KEY (scope, identity, selected_at, family, key)','p','false','false'),
 ('pn_epoch_references','FOREIGN KEY (scope, identity) REFERENCES pn_epoch_results(scope, identity)','f','false','false'),
 ('pn_epoch_references','FOREIGN KEY (scope, judgement_origin) REFERENCES pn_epoch_results(scope, identity)','f','false','false'),
 ('pn_epoch_references','NOT NULL scope','n','false','false'),
 ('pn_epoch_references','CHECK ((selected_at >= 0))','c','false','false'),
 ('pn_epoch_references','NOT NULL selected_at','n','false','false'),
 ('pn_epoch_result_debits','NOT NULL act_family','n','false','false'),
 ('pn_epoch_result_debits','NOT NULL act_sequence','n','false','false'),
 ('pn_epoch_result_debits','NOT NULL author','n','false','false'),
 ('pn_epoch_result_debits','CHECK ((octet_length(origin) = 32))','c','false','false'),
 ('pn_epoch_result_debits','CHECK ((origin_depth > 0))','c','false','false'),
 ('pn_epoch_result_debits','NOT NULL origin_depth','n','false','false'),
 ('pn_epoch_result_debits','NOT NULL origin','n','false','false'),
 ('pn_epoch_result_debits','PRIMARY KEY (scope, origin, author, act_sequence, act_family)','p','false','false'),
 ('pn_epoch_result_debits','NOT NULL scope','n','false','false'),
 ('pn_epoch_result_debits','FOREIGN KEY (scope, origin, author, act_sequence, act_family) REFERENCES pn_epoch_debits(scope, origin, author, act_sequence, act_family)','f','false','false'),
 ('pn_epoch_result_debits','FOREIGN KEY (scope, origin, segment, origin_depth) REFERENCES pn_epoch_results(scope, identity, segment, depth)','f','false','false'),
 ('pn_epoch_result_debits','CHECK ((octet_length(segment) = 32))','c','false','false'),
 ('pn_epoch_result_debits','NOT NULL segment','n','false','false'),
 ('pn_epoch_results','CHECK ((((depth = 1) AND (parent IS NULL) AND (parent_depth IS NULL) AND (parent_segment IS NULL)) OR ((depth > 1) AND (parent IS NOT NULL) AND (parent_depth IS NOT NULL) AND (parent_segment IS NOT NULL) AND (parent_depth = (depth - 1)))))','c','false','false'),
 ('pn_epoch_results','CHECK (((identity = segment) OR (parent_segment = segment)))','c','false','false'),
 ('pn_epoch_results','CHECK (((depth <> 1) OR (identity = segment)))','c','false','false'),
 ('pn_epoch_results','CHECK ((debit_count >= 0))','c','false','false'),
 ('pn_epoch_results','NOT NULL debit_count','n','false','false'),
 ('pn_epoch_results','CHECK ((depth > 0))','c','false','false'),
 ('pn_epoch_results','NOT NULL depth','n','false','false'),
 ('pn_epoch_results','NOT NULL generation','n','false','false'),
 ('pn_epoch_results','CHECK ((octet_length(identity) = 32))','c','false','false'),
 ('pn_epoch_results','NOT NULL identity','n','false','false'),
 ('pn_epoch_results','CHECK ((package_bytes > 0))','c','false','false'),
 ('pn_epoch_results','NOT NULL package_bytes','n','false','false'),
 ('pn_epoch_results','CHECK ((package_chunks > 0))','c','false','false'),
 ('pn_epoch_results','NOT NULL package_chunks','n','false','false'),
 ('pn_epoch_results','CHECK ((octet_length(parent) = 32))','c','false','false'),
 ('pn_epoch_results','CHECK ((octet_length(parent_segment) = 32))','c','false','false'),
 ('pn_epoch_results','PRIMARY KEY (scope, identity)','p','false','false'),
 ('pn_epoch_results','CHECK ((reference_count >= 0))','c','false','false'),
 ('pn_epoch_results','NOT NULL reference_count','n','false','false'),
 ('pn_epoch_results','FOREIGN KEY (scope) REFERENCES pn_epoch_scopes(scope)','f','false','false'),
 ('pn_epoch_results','FOREIGN KEY (scope, generation) REFERENCES pn_admission_generations(scope, generation)','f','false','false'),
 ('pn_epoch_results','UNIQUE (scope, identity, depth)','u','false','false'),
 ('pn_epoch_results','UNIQUE (scope, identity, parent, parent_segment, parent_depth)','u','false','false'),
 ('pn_epoch_results','UNIQUE (scope, identity, segment, depth)','u','false','false'),
 ('pn_epoch_results','NOT NULL scope','n','false','false'),
 ('pn_epoch_results','FOREIGN KEY (scope, parent, parent_segment, parent_depth) REFERENCES pn_epoch_results(scope, identity, segment, depth)','f','false','false'),
 ('pn_epoch_results','UNIQUE (scope, segment, depth)','u','false','false'),
 ('pn_epoch_results','FOREIGN KEY (scope, segment) REFERENCES pn_epoch_branches(scope, segment)','f','false','false'),
 ('pn_epoch_results','CHECK ((octet_length(segment) = 32))','c','false','false'),
 ('pn_epoch_results','NOT NULL segment','n','false','false'),
 ('pn_epoch_scopes','CHECK ((octet_length(context_root) = 32))','c','false','false'),
 ('pn_epoch_scopes','NOT NULL context_root','n','false','false'),
 ('pn_epoch_scopes','PRIMARY KEY (scope)','p','false','false'),
 ('pn_epoch_scopes','CHECK (((octet_length(scope) >= 1) AND (octet_length(scope) <= 1024)))','c','false','false'),
 ('pn_epoch_scopes','FOREIGN KEY (scope, context_root) REFERENCES pn_epoch_results(scope, identity) DEFERRABLE INITIALLY DEFERRED','f','true','true'),
 ('pn_epoch_scopes','NOT NULL scope','n','false','false')
), actual_constraints AS (
 SELECT r.relname::text,pg_get_constraintdef(c.oid),c.contype::text,c.condeferrable::text,c.condeferred::text
 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
 WHERE r.relnamespace='public'::regnamespace AND r.relname IN (SELECT relation FROM expected_columns)
), expected_indexes(relation,name,definition) AS (VALUES
 ('pn_admission_closures','pn_admission_closures_generation','CREATE INDEX pn_admission_closures_generation ON public.pn_admission_closures USING btree (scope, generation, family, key)'),
 ('pn_admission_closures','pn_admission_closures_pkey','CREATE UNIQUE INDEX pn_admission_closures_pkey ON public.pn_admission_closures USING btree (family, key, edition)'),
 ('pn_admission_generations','pn_admission_generations_pkey','CREATE UNIQUE INDEX pn_admission_generations_pkey ON public.pn_admission_generations USING btree (scope, generation)'),
 ('pn_admission_generations','pn_admission_generations_scope_label_key','CREATE UNIQUE INDEX pn_admission_generations_scope_label_key ON public.pn_admission_generations USING btree (scope, label)'),
 ('pn_admission_versions','pn_admission_versions_generation','CREATE INDEX pn_admission_versions_generation ON public.pn_admission_versions USING btree (scope, generation, family, key)'),
 ('pn_admission_versions','pn_admission_versions_pkey','CREATE UNIQUE INDEX pn_admission_versions_pkey ON public.pn_admission_versions USING btree (family, key, edition)'),
 ('pn_epoch_branches','pn_epoch_branches_pkey','CREATE UNIQUE INDEX pn_epoch_branches_pkey ON public.pn_epoch_branches USING btree (scope, segment)'),
 ('pn_epoch_debit_chunks','pn_epoch_debit_chunks_pkey','CREATE UNIQUE INDEX pn_epoch_debit_chunks_pkey ON public.pn_epoch_debit_chunks USING btree (scope, origin, author, act_sequence, act_family, ordinal)'),
 ('pn_epoch_debits','pn_epoch_debits_pkey','CREATE UNIQUE INDEX pn_epoch_debits_pkey ON public.pn_epoch_debits USING btree (scope, origin, author, act_sequence, act_family)'),
 ('pn_epoch_package_chunks','pn_epoch_package_chunks_pkey','CREATE UNIQUE INDEX pn_epoch_package_chunks_pkey ON public.pn_epoch_package_chunks USING btree (scope, identity, ordinal)'),
 ('pn_epoch_references','pn_epoch_references_pkey','CREATE UNIQUE INDEX pn_epoch_references_pkey ON public.pn_epoch_references USING btree (scope, identity, selected_at, family, key)'),
 ('pn_epoch_result_debits','pn_epoch_result_debits_path','CREATE INDEX pn_epoch_result_debits_path ON public.pn_epoch_result_debits USING btree (scope, segment, origin_depth, author, act_sequence, act_family)'),
 ('pn_epoch_result_debits','pn_epoch_result_debits_pkey','CREATE UNIQUE INDEX pn_epoch_result_debits_pkey ON public.pn_epoch_result_debits USING btree (scope, origin, author, act_sequence, act_family)'),
 ('pn_epoch_results','pn_epoch_results_children','CREATE INDEX pn_epoch_results_children ON public.pn_epoch_results USING btree (scope, parent, identity)'),
 ('pn_epoch_results','pn_epoch_results_pkey','CREATE UNIQUE INDEX pn_epoch_results_pkey ON public.pn_epoch_results USING btree (scope, identity)'),
 ('pn_epoch_results','pn_epoch_results_scope_identity_depth_key','CREATE UNIQUE INDEX pn_epoch_results_scope_identity_depth_key ON public.pn_epoch_results USING btree (scope, identity, depth)'),
 ('pn_epoch_results','pn_epoch_results_scope_identity_parent_parent_segment_paren_key','CREATE UNIQUE INDEX pn_epoch_results_scope_identity_parent_parent_segment_paren_key ON public.pn_epoch_results USING btree (scope, identity, parent, parent_segment, parent_depth)'),
 ('pn_epoch_results','pn_epoch_results_scope_identity_segment_depth_key','CREATE UNIQUE INDEX pn_epoch_results_scope_identity_segment_depth_key ON public.pn_epoch_results USING btree (scope, identity, segment, depth)'),
 ('pn_epoch_results','pn_epoch_results_scope_segment_depth_key','CREATE UNIQUE INDEX pn_epoch_results_scope_segment_depth_key ON public.pn_epoch_results USING btree (scope, segment, depth)'),
 ('pn_epoch_scopes','pn_epoch_scopes_pkey','CREATE UNIQUE INDEX pn_epoch_scopes_pkey ON public.pn_epoch_scopes USING btree (scope)')
), actual_indexes AS (
 SELECT r.relname::text,x.relname::text,pg_get_indexdef(i.indexrelid)
 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class r ON r.oid=i.indrelid JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid
 WHERE r.relnamespace='public'::regnamespace AND r.relname IN (SELECT relation FROM expected_columns)
)
SELECT NOT EXISTS ((SELECT * FROM expected_columns EXCEPT ALL SELECT * FROM actual_columns)
 UNION ALL (SELECT * FROM actual_columns EXCEPT ALL SELECT * FROM expected_columns))
 AND NOT EXISTS ((SELECT * FROM expected_constraints EXCEPT ALL SELECT * FROM actual_constraints)
 UNION ALL (SELECT * FROM actual_constraints EXCEPT ALL SELECT * FROM expected_constraints))
 AND NOT EXISTS ((SELECT * FROM expected_indexes EXCEPT ALL SELECT * FROM actual_indexes)
 UNION ALL (SELECT * FROM actual_indexes EXCEPT ALL SELECT * FROM expected_indexes))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
 WHERE r.relnamespace='public'::regnamespace AND r.relname IN (SELECT relation FROM expected_columns)
 AND (NOT c.convalidated OR NOT c.conenforced))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class r ON r.oid=i.indrelid
 JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=x.relam
 WHERE r.relnamespace='public'::regnamespace AND r.relname IN (SELECT relation FROM expected_columns)
 AND (NOT i.indisvalid OR NOT i.indisready OR i.indnullsnotdistinct OR i.indnkeyatts<>i.indnatts
 OR am.amname<>'btree' OR i.indpred IS NOT NULL OR i.indexprs IS NOT NULL
 OR EXISTS (SELECT 1 FROM unnest(i.indoption) option WHERE option<>0)
 OR EXISTS (SELECT 1 FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
 JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid AND a.attnum=k.number
 WHERE i.indcollation[k.position-1]<>a.attcollation)))
 AND (SELECT count(*) = 2 AND bool_and(pg_get_constraintdef(c.oid) = 'PRIMARY KEY (family, key, edition)'
 AND c.convalidated AND c.conenforced AND NOT c.condeferrable AND NOT c.condeferred
 AND i.indisvalid AND i.indisready AND NOT i.indnullsnotdistinct)
 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
 JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
 WHERE r.relnamespace='public'::regnamespace AND r.relname IN ('pn_versions','pn_closures') AND c.contype='p')
";
