//! One atomic retained-result transaction using the tree reader's bounded extraction.
//! (´[ROOT-amend:storage:admitted-transaction]´)

use super::super::{Identity, Meter, ReadBudget, Selected, Usage, checked_result_input, unqualified};
use super::{
    Error, Header, HistoryState, Range, ReadAccess, ServerJudgement, ServerReader, ServerTree, Statement, StatementParameter,
    StatementTransaction, StorageError, identity, observed, positive, projection, spans, text, unsigned,
};
use crate::admitted_result::{DebitVintage, position::Retained};

const CHUNK: usize = 262_144;

struct LocalDebit {
    index: usize,
    sequence: [u8; 20],
    sequence_start: usize,
    bytes: i64,
    chunks: i64,
    boundary: i64,
}

impl LocalDebit {
    fn new(index: usize, vintage: &DebitVintage) -> Self {
        let mut sequence = [0; 20];
        let mut number = vintage.key.act.sequence;
        let mut start = sequence.len();
        loop {
            start -= 1;
            sequence[start] = b'0' + u8::try_from(number % 10).unwrap();
            number /= 10;
            if number == 0 {
                break;
            }
        }
        Self {
            index,
            sequence,
            sequence_start: start,
            bytes: i64::try_from(vintage.bytes.len()).unwrap(),
            chunks: i64::try_from(vintage.bytes.len().div_ceil(CHUNK)).unwrap(),
            boundary: vintage.disclosure.boundary.cast_signed(),
        }
    }
    fn sequence(&self) -> &str {
        std::str::from_utf8(&self.sequence[self.sequence_start..]).unwrap_or("0")
    }
}

struct Plan<'a> {
    judgement: ServerJudgement<'a>,
    reference_order: Vec<usize>,
    local: Vec<LocalDebit>,
    new_scope: bool,
    new_branch: bool,
    segment: Identity,
    parent_segment: Option<Identity>,
    parent_depth: Option<i64>,
    depth: i64,
    package_bytes: i64,
    package_chunks: i64,
    references: i64,
    debits: i64,
}

#[derive(Clone, Copy)]
struct Scalars {
    depth: i64,
    package_bytes: i64,
    package_chunks: i64,
    references: i64,
    debits: i64,
}

fn chunk_count(length: usize) -> Result<i64, Error> {
    i64::try_from(length.div_ceil(CHUNK)).map_err(|_| StorageError::Representation.into())
}

fn checked_scalars(input: &Retained) -> Result<Scalars, Error> {
    let (_, _, _, depth) = input.event();
    let scalars = Scalars {
        depth: i64::try_from(depth).map_err(|_| StorageError::Representation)?,
        package_bytes: i64::try_from(input.bytes().len()).map_err(|_| StorageError::Representation)?,
        package_chunks: chunk_count(input.bytes().len())?,
        references: i64::try_from(input.declarations().len()).map_err(|_| StorageError::Representation)?,
        debits: i64::try_from(input.debits().len()).map_err(|_| StorageError::Representation)?,
    };
    for use_ in input.declarations() {
        i64::try_from(use_.selected_at).map_err(|_| StorageError::Representation)?;
        let version = &use_.version;
        if !unqualified(version.family) {
            i64::try_from(version.announced_at).map_err(|_| StorageError::Representation)?;
            i64::try_from(version.opens_at).map_err(|_| StorageError::Representation)?;
        }
    }
    for vintage in input.debits() {
        i64::try_from(vintage.bytes.len()).map_err(|_| StorageError::Representation)?;
        chunk_count(vintage.bytes.len())?;
    }
    Ok(scalars)
}

pub(super) async fn commit<'a>(
    store: &mut ServerTree,
    input: &'a Retained,
    label: Option<&'a str>,
    budget: ReadBudget,
    usage: &mut Usage,
) -> Result<ServerJudgement<'a>, Error> {
    *usage = Usage::default();
    let label = checked_result_input(input, label)?;
    let scope = ServerReader::scope(input.event().0)?;
    let scope = scope.text()?;
    let scalars = checked_scalars(input)?;
    let mut meter = Meter {
        limit: budget,
        used: Usage::default(),
    };
    let transaction = store.session.client.transaction(store.session.store_requests.clone()).await?;
    let result = {
        let mut writer = Writer {
            transaction: &transaction,
            meter: &mut meter,
            #[cfg(test)]
            hook: &mut store.generation_hook,
        };
        writer.run(input, label, scope, scalars).await
    };
    *usage = meter.used;
    super::finish_transaction(transaction, result, || {
        #[cfg(test)]
        store.generation_hook.before("COMMIT")?;
        Ok(())
    })
    .await
}

struct Writer<'a, 'b> {
    transaction: &'a StatementTransaction<'b>,
    meter: &'a mut Meter,
    #[cfg(test)]
    hook: &'a mut super::generation::Hook,
}

impl Writer<'_, '_> {
    fn read(&mut self) -> ReadAccess<'_, '_> {
        ReadAccess {
            transaction: self.transaction,
            meter: self.meter,
            #[cfg(test)]
            hook: Some(self.hook),
        }
    }

    async fn request(
        &mut self,
        statement: Statement,
        params: &[StatementParameter<'_>],
        limit: usize,
        maximum: usize,
        probe: bool,
    ) -> Result<Vec<super::StatementRow>, Error> {
        self.read().request(statement, params, limit, maximum, probe).await
    }

    async fn execute(&mut self, statement: Statement, params: &[StatementParameter<'_>]) -> Result<(), Error> {
        super::execute_one(self.transaction, statement, params, || {
            #[cfg(test)]
            self.hook.before(point(statement))?;
            Ok(())
        })
        .await
    }

    async fn run<'a>(
        &mut self,
        input: &'a Retained,
        label: &'a str,
        scope: &str,
        scalars: Scalars,
    ) -> Result<ServerJudgement<'a>, Error> {
        #[cfg(test)]
        self.hook.before("LockHistory")?;
        observed(self.transaction.batch_execute(Statement::LockHistory)).await?;
        let (_, identity, _, _) = input.event();
        let rows = self
            .request(Statement::ReadEpoch, &[&scope, &&identity[..]], 1, 278, false)
            .await?;
        if let Some(row) = rows.first() {
            let header = Header::read(row)?;
            if header.identity != *identity {
                return Err(StorageError::CorruptHistory.into());
            }
            self.retry(input, label, scope, header).await
        } else {
            self.fresh(input, label, scope, scalars).await
        }
    }

    async fn retry<'a>(
        &mut self,
        input: &'a Retained,
        label: &'a str,
        scope: &str,
        header: Header,
    ) -> Result<ServerJudgement<'a>, Error> {
        let (_, result_identity, parent, depth) = input.event();
        let retained_label = self.read().generation(scope, header.generation).await?;
        let bytes = self.read().package(scope, &header).await?;
        let validated = spans::Validated::new(&bytes, self.meter)?;
        if header.parent != parent.copied()
            || header.identity != *result_identity
            || header.depth != depth
            || retained_label != label
            || bytes != input.bytes()
        {
            return Err(StorageError::EpochConflict.into());
        }
        let ranges = self.read().ranges(scope, &header).await?;
        let selected = self.read().selections(scope, &header, &ranges, false).await?;
        let debits = self.read().debits(scope, &header, &ranges).await?;
        projection::validate(input.event().0, &header, &validated, &selected, &debits, self.meter)?;
        let roots = self.request(Statement::ReadScope, &[&scope], 1, 50, false).await?;
        let root = identity(roots.first().ok_or(StorageError::CorruptHistory)?, 0, 1)?;
        let root_header = self.read().header(scope, root).await?;
        if root_header.depth != 1 || root_header.parent.is_some() {
            return Err(StorageError::CorruptHistory.into());
        }
        let root_bytes = self.read().package(scope, &root_header).await?;
        let root_document = spans::Validated::new(&root_bytes, self.meter)?;
        projection::context(&validated, &root_document)?;
        if let Some(parent) = header.parent {
            let parent = self.read().header(scope, parent).await?;
            if parent.depth.checked_add(1) != Some(header.depth) || Some(parent.segment) != header.parent_segment {
                return Err(StorageError::CorruptHistory.into());
            }
            self.read().generation(scope, parent.generation).await?;
            let parent_bytes = self.read().package(scope, &parent).await?;
            let parent_document = spans::Validated::new(&parent_bytes, self.meter)?;
            projection::extends(&validated, &parent_document)?;
        }
        if selected.len() != input.declarations().len() || debits.len() != input.debits().len() {
            return Err(StorageError::CorruptHistory.into());
        }
        for debit in &debits {
            let Some(wanted) = input.debits().iter().find(|item| item.key.act == debit.act) else {
                return Err(StorageError::CorruptHistory.into());
            };
            if wanted.bytes != debit.bytes || wanted.disclosure.boundary != debit.writing_boundary {
                return Err(StorageError::CorruptHistory.into());
            }
            if debit.origin != header.identity {
                let origin = self.read().header(scope, debit.origin).await?;
                let origin_bytes = self.read().package(scope, &origin).await?;
                let origin_document = spans::Validated::new(&origin_bytes, self.meter)?;
                projection::debit_origin(&origin_document, debit)?;
            }
        }
        let mut selections = Vec::new();
        self.meter.reserve(&mut selections, input.declarations().len())?;
        for use_ in input.declarations() {
            let Some(found) = selected.iter().find(|item| item.use_ == *use_) else {
                return Err(StorageError::CorruptHistory.into());
            };
            selections.push(Selected {
                use_,
                origin: found.origin,
            });
        }
        Ok(ServerJudgement {
            label,
            generation: 1,
            selections,
            inserted: false,
        })
    }

    async fn fresh<'a>(
        &mut self,
        input: &'a Retained,
        label: &'a str,
        scope: &str,
        scalars: Scalars,
    ) -> Result<ServerJudgement<'a>, Error> {
        let (_, result_identity, parent, _) = input.event();
        let (root_exists, prior) = self.context_and_parent(input, scope).await?;
        let (inherited, prior_ranges) = if let Some(prior) = &prior {
            let ranges = self.read().ranges(scope, prior).await?;
            let inherited = self.read().debits(scope, prior, &ranges).await?;
            (inherited, ranges)
        } else {
            (Vec::new(), Vec::new())
        };
        if !root_exists && prior.is_some() {
            return Err(StorageError::CorruptHistory.into());
        }
        let generation = self
            .request(Statement::ReadAdmissionGeneration, &[&scope, &1_i64], 1, 1102, false)
            .await?;
        let row = generation.first().ok_or(if root_exists || prior.is_some() {
            StorageError::CorruptHistory.into()
        } else {
            Error::UnknownGenerationLabel
        })?;
        let previous: Option<i64> = row.try_get(1).map_err(|_| StorageError::CorruptHistory)?;
        if positive(row, 0)? != 1
            || previous.is_some()
            || positive(row, 2)? != 1
            || text(row, 5, 6, 1024)? != label
            || unsigned(row, 3).is_err()
            || unsigned(row, 4).is_err()
            || prior.as_ref().is_some_and(|p| p.generation != 1)
        {
            return Err(StorageError::CorruptHistory.into());
        }

        let selections = self
            .selected_origins(input, scope, *result_identity, prior.as_ref(), &prior_ranges)
            .await?;
        let mut local_indices = Vec::new();
        self.meter.reserve(&mut local_indices, input.debits().len())?;
        for (index, vintage) in input.debits().iter().enumerate() {
            if let Some(old) = inherited.iter().find(|old| old.act == vintage.key.act) {
                if old.bytes != vintage.bytes || old.writing_boundary != vintage.disclosure.boundary {
                    return Err(StorageError::DebitConflict.into());
                }
            } else {
                local_indices.push(index);
            }
        }
        if inherited
            .iter()
            .any(|old| !input.debits().iter().any(|v| v.key.act == old.act))
        {
            return Err(StorageError::DebitConflict.into());
        }
        let continuation = if let Some(parent) = parent {
            let rows = self
                .request(Statement::HasChild, &[&scope, &&parent[..]], 1, 7, false)
                .await?;
            let exists: bool = rows
                .first()
                .ok_or(StorageError::CorruptHistory)?
                .try_get(0)
                .map_err(|_| StorageError::CorruptHistory)?;
            !exists
        } else {
            false
        };
        let segment = if continuation {
            prior.as_ref().ok_or(StorageError::CorruptHistory)?.segment
        } else {
            *result_identity
        };
        let plan = self.prepare(
            input,
            label,
            selections,
            local_indices,
            (!root_exists, !continuation, segment, prior.as_ref()),
            scalars,
        )?;
        self.insert(input, scope, &plan).await?;
        Ok(plan.judgement)
    }

    async fn context_and_parent(&mut self, input: &Retained, scope: &str) -> Result<(bool, Option<Header>), Error> {
        let (_, _, parent, depth) = input.event();
        let rows = self.request(Statement::ReadScope, &[&scope], 1, 50, false).await?;
        let context_root = rows.first().map(|row| identity(row, 0, 1)).transpose()?;
        if let Some(root) = context_root {
            let root_header = self.read().header(scope, root).await?;
            if root_header.depth != 1 || root_header.parent.is_some() {
                return Err(StorageError::CorruptHistory.into());
            }
            let root_bytes = self.read().package(scope, &root_header).await?;
            let current = spans::Validated::new(input.bytes(), self.meter)?;
            let retained = spans::Validated::new(&root_bytes, self.meter)?;
            if !projection::context_match(&current, &retained)? {
                return Err(Error::ContextConflict);
            }
        }
        let prior = if let Some(parent) = parent {
            let rows = self
                .request(Statement::ReadEpoch, &[&scope, &&parent[..]], 1, 278, false)
                .await?;
            let row = rows.first().ok_or(Error::PredecessorMismatch)?;
            let header = Header::read(row)?;
            if header.identity != *parent || header.depth.checked_add(1) != Some(depth) {
                return Err(StorageError::CorruptHistory.into());
            }
            let bytes = self.read().package(scope, &header).await?;
            let current = spans::Validated::new(input.bytes(), self.meter)?;
            let retained = spans::Validated::new(&bytes, self.meter)?;
            if !projection::extends_match(&current, &retained)? {
                return Err(Error::PredecessorMismatch);
            }
            Some(header)
        } else {
            None
        };
        Ok((context_root.is_some(), prior))
    }

    async fn selected_origins<'a>(
        &mut self,
        input: &'a Retained,
        scope: &str,
        result_identity: Identity,
        prior: Option<&Header>,
        prior_ranges: &[Range],
    ) -> Result<Vec<Selected<'a>>, Error> {
        let mut selections = Vec::new();
        self.meter.reserve(&mut selections, input.declarations().len())?;
        for use_ in input.declarations() {
            let origin = if unqualified(use_.version.family) {
                let old = if let Some(prior) = prior {
                    self.read().use_at_optional(scope, prior.identity, use_).await?
                } else {
                    None
                };
                if let Some(old) = old {
                    if old.use_ != *use_ {
                        return Err(StorageError::SelectedContentMismatch.into());
                    }
                    self.read()
                        .selection_origin(scope, prior.ok_or(StorageError::CorruptHistory)?, prior_ranges, &old, false)
                        .await?;
                    old.origin
                } else {
                    match self.read().history(scope, use_).await? {
                        HistoryState::Equal => result_identity,
                        HistoryState::Missing => return Err(StorageError::MissingSelectedVersion.into()),
                        HistoryState::Different => return Err(StorageError::SelectedContentMismatch.into()),
                        HistoryState::Inactive => return Err(StorageError::SelectedVersionNotEffective.into()),
                    }
                }
            } else {
                let version = &use_.version;
                let rows = self
                    .request(
                        Statement::HasVersion,
                        &[&version.family.name(), &version.key, &version.edition],
                        1,
                        7,
                        false,
                    )
                    .await?;
                let exists: bool = rows
                    .first()
                    .ok_or(StorageError::CorruptHistory)?
                    .try_get(0)
                    .map_err(|_| StorageError::CorruptHistory)?;
                if exists {
                    return Err(StorageError::CorruptHistory.into());
                }
                result_identity
            };
            selections.push(Selected { use_, origin });
        }
        Ok(selections)
    }

    fn prepare<'a>(
        &mut self,
        input: &'a Retained,
        label: &'a str,
        selections: Vec<Selected<'a>>,
        local_indices: Vec<usize>,
        (new_scope, new_branch, segment, prior): (bool, bool, Identity, Option<&Header>),
        scalars: Scalars,
    ) -> Result<Plan<'a>, Error> {
        let (_, _, _, depth) = input.event();
        let mut reference_order = Vec::new();
        self.meter.reserve(&mut reference_order, selections.len())?;
        reference_order.extend(0..selections.len());
        reference_order.sort_unstable_by(|a, b| {
            let a = selections[*a].use_;
            let b = selections[*b].use_;
            (a.selected_at, a.version.family.name(), &a.version.key, &a.version.edition).cmp(&(
                b.selected_at,
                b.version.family.name(),
                &b.version.key,
                &b.version.edition,
            ))
        });
        let mut local = Vec::new();
        self.meter.reserve(&mut local, local_indices.len())?;
        for index in local_indices {
            local.push(LocalDebit::new(index, &input.debits()[index]));
        }
        local.sort_unstable_by(|a, b| input.debits()[a.index].key.act.cmp(&input.debits()[b.index].key.act));
        let plan = Plan {
            judgement: ServerJudgement {
                label,
                generation: 1,
                selections,
                inserted: true,
            },
            reference_order,
            local,
            new_scope,
            new_branch,
            segment,
            parent_segment: prior.map(|p| p.segment),
            parent_depth: prior.map(|p| p.depth.cast_signed()),
            depth: scalars.depth,
            package_bytes: scalars.package_bytes,
            package_chunks: scalars.package_chunks,
            references: scalars.references,
            debits: scalars.debits,
        };
        let (_, identity, parent, _) = input.event();
        let header = Header {
            identity: *identity,
            parent: parent.copied(),
            parent_segment: plan.parent_segment,
            segment: plan.segment,
            depth,
            generation: 1,
            bytes: plan.package_bytes.cast_unsigned(),
            chunks: plan.package_chunks.cast_unsigned(),
            references: plan.references.cast_unsigned(),
            debits: plan.debits.cast_unsigned(),
        };
        let document = spans::Validated::new(input.bytes(), self.meter)?;
        projection::validate_input(
            input.event().0,
            &header,
            &document,
            &plan.judgement.selections,
            input.debits(),
            self.meter,
        )?;
        Ok(plan)
    }

    async fn insert(&mut self, input: &Retained, scope: &str, plan: &Plan<'_>) -> Result<(), Error> {
        let (_, identity, _, _) = input.event();
        self.insert_header(input, scope, plan).await?;
        let mut written_chunks = 0_i64;
        for part in input.bytes().chunks(CHUNK) {
            let ordinal = written_chunks;
            self.execute(Statement::InsertEpochChunk, &[&scope, &&identity[..], &ordinal, &part])
                .await?;
            written_chunks += 1;
        }
        let mut written_observations = 0usize;
        for use_ in input.declarations().iter().filter(|use_| !unqualified(use_.version.family)) {
            let version = &use_.version;
            let announced = version.announced_at.cast_signed();
            let opens = version.opens_at.cast_signed();
            let payload = version.payload.as_ref();
            let content = payload.map(|p| p.bytes.as_slice());
            let digest = payload.map(|p| p.digest.as_slice());
            let disclosure = payload.and_then(|p| p.disclosure.as_ref().map(<[u8; 32]>::as_slice));
            self.execute(
                Statement::Insert,
                &[
                    &version.family.name(),
                    &version.key,
                    &version.edition,
                    &announced,
                    &opens,
                    &content,
                    &digest,
                    &disclosure,
                ],
            )
            .await?;
            written_observations += 1;
        }
        let mut written_references = 0_i64;
        for index in &plan.reference_order {
            let selected = &plan.judgement.selections[*index];
            let version = &selected.use_.version;
            let at = selected.use_.selected_at.cast_signed();
            self.execute(
                Statement::InsertEpochReference,
                &[
                    &scope,
                    &&identity[..],
                    &at,
                    &version.family.name(),
                    &version.key,
                    &version.edition,
                    &&selected.origin[..],
                ],
            )
            .await?;
            written_references += 1;
        }
        let written_local = self.insert_debits(input, scope, plan).await?;
        if written_chunks != plan.package_chunks
            || written_references != plan.references
            || written_local != plan.local.len()
            || written_observations
                != input
                    .declarations()
                    .iter()
                    .filter(|use_| !unqualified(use_.version.family))
                    .count()
        {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(())
    }

    async fn insert_header(&mut self, input: &Retained, scope: &str, plan: &Plan<'_>) -> Result<(), Error> {
        let (_, identity, parent, _) = input.event();
        let parent = parent.map(<[u8; 32]>::as_slice);
        let parent_segment = plan.parent_segment.as_ref().map(<[u8; 32]>::as_slice);
        if plan.new_scope {
            self.execute(Statement::InsertScope, &[&scope, &&identity[..]]).await?;
        }
        if plan.new_branch {
            let fork_depth = plan.parent_depth.unwrap_or(0);
            self.execute(
                Statement::InsertBranch,
                &[&scope, &&plan.segment[..], &plan.depth, &parent_segment, &parent, &fork_depth],
            )
            .await?;
        }
        self.execute(
            Statement::InsertEpoch,
            &[
                &scope,
                &&identity[..],
                &plan.depth,
                &parent,
                &plan.parent_depth,
                &parent_segment,
                &&plan.segment[..],
                &1_i64,
                &plan.package_bytes,
                &plan.package_chunks,
                &plan.references,
                &plan.debits,
            ],
        )
        .await?;
        Ok(())
    }

    async fn insert_debits(&mut self, input: &Retained, scope: &str, plan: &Plan<'_>) -> Result<usize, Error> {
        let (_, identity, _, _) = input.event();
        for local in &plan.local {
            let vintage = &input.debits()[local.index];
            let act = &vintage.key.act;
            let sequence = local.sequence();
            self.execute(
                Statement::InsertDebit,
                &[
                    &scope,
                    &&identity[..],
                    &act.author,
                    &sequence,
                    &act.family,
                    &local.boundary,
                    &local.bytes,
                    &local.chunks,
                ],
            )
            .await?;
            let mut written = 0_i64;
            for part in vintage.bytes.chunks(CHUNK) {
                let ordinal = written;
                self.execute(
                    Statement::InsertDebitChunk,
                    &[&scope, &&identity[..], &act.author, &sequence, &act.family, &ordinal, &part],
                )
                .await?;
                written += 1;
            }
            if written != local.chunks {
                return Err(StorageError::CorruptHistory.into());
            }
        }
        let mut written_local = 0usize;
        for local in &plan.local {
            let vintage = &input.debits()[local.index];
            let act = &vintage.key.act;
            let sequence = local.sequence();
            self.execute(
                Statement::InsertEpochDebit,
                &[
                    &scope,
                    &&identity[..],
                    &&plan.segment[..],
                    &plan.depth,
                    &act.author,
                    &sequence,
                    &act.family,
                ],
            )
            .await?;
            written_local += 1;
        }
        Ok(written_local)
    }
}

#[cfg(test)]
fn point(statement: Statement) -> &'static str {
    match statement {
        Statement::InsertScope => "InsertScope",
        Statement::InsertBranch => "InsertBranch",
        Statement::InsertEpoch => "InsertEpoch",
        Statement::InsertEpochChunk => "InsertEpochChunk",
        Statement::Insert => "Insert",
        Statement::InsertEpochReference => "InsertEpochReference",
        Statement::InsertDebit => "InsertDebit",
        Statement::InsertDebitChunk => "InsertDebitChunk",
        Statement::InsertEpochDebit => "InsertEpochDebit",
        _ => "OtherInsert",
    }
}
