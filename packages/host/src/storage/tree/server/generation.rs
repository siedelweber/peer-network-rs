//! Atomic first-generation installation through the existing statement wrapper.
//! (´[ROOT-amend:storage:admitted-transaction]´)

use super::super::{Closure, Generation, Meter, ReadBudget, Usage};
use super::{Error, ServerReader, ServerTree, Statement, StatementParameter, StatementTransaction, StorageError};
use super::{copy_text, decode_version, family, positive, read_request, text, unsigned};

pub(super) struct Plan {
    scope: super::Scope,
    pub(super) version_order: Vec<usize>,
    pub(super) closure_order: Vec<usize>,
    pub(super) version_count: i64,
    pub(super) closure_count: i64,
}

impl Plan {
    fn new(input: &Generation, meter: &mut Meter, version_count: i64, closure_count: i64) -> Result<Self, Error> {
        let scope = ServerReader::scope(&input.scope)?;
        let mut version_order = Vec::new();
        let mut closure_order = Vec::new();
        meter.reserve(&mut version_order, input.versions.len())?;
        meter.reserve(&mut closure_order, input.closures.len())?;
        version_order.extend(0..input.versions.len());
        closure_order.extend(0..input.closures.len());
        version_order.sort_unstable_by(|a, b| {
            let a = &input.versions[*a];
            let b = &input.versions[*b];
            (a.family.name(), a.key.as_str(), a.opens_at).cmp(&(b.family.name(), b.key.as_str(), b.opens_at))
        });
        closure_order.sort_unstable_by(|a, b| {
            let a = &input.closures[*a];
            let b = &input.closures[*b];
            (a.family.name(), a.key.as_str(), a.closes_at).cmp(&(b.family.name(), b.key.as_str(), b.closes_at))
        });
        Ok(Self {
            scope,
            version_order,
            closure_order,
            version_count,
            closure_count,
        })
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(super) struct Hook {
    pub(super) stop_at: Option<usize>,
    pub(super) points: Vec<&'static str>,
}

#[cfg(test)]
impl Hook {
    fn before(&mut self, point: &'static str) -> Result<(), Error> {
        self.points.push(point);
        if self.stop_at == Some(self.points.len()) {
            return Err(StorageError::Injected.into());
        }
        Ok(())
    }
}

pub(super) async fn install(
    store: &mut ServerTree,
    input: &Generation,
    budget: ReadBudget,
    usage: &mut Usage,
) -> Result<bool, Error> {
    *usage = Usage::default();
    let mut meter = Meter {
        limit: budget,
        used: Usage::default(),
    };
    let plan = match prepare(input, &mut meter) {
        Ok(plan) => plan,
        Err(error) => {
            *usage = meter.used;
            return Err(error);
        }
    };
    *usage = meter.used;
    let transaction = store.session.client.transaction(store.session.store_requests.clone()).await?;
    let result = {
        let mut writer = Writer {
            transaction: &transaction,
            meter: &mut meter,
            #[cfg(test)]
            hook: &mut store.generation_hook,
        };
        writer.run(input, &plan).await
    };
    *usage = meter.used;
    match result {
        Ok(inserted) => {
            #[cfg(test)]
            if let Err(error) = store.generation_hook.before("COMMIT") {
                return Err(transaction.refuse(error).await);
            }
            transaction.commit().await?;
            Ok(inserted)
        }
        Err(error) => Err(transaction.refuse(error).await),
    }
}

pub(super) fn prepare(input: &Generation, meter: &mut Meter) -> Result<Plan, Error> {
    // These checks are shared with the memory model and precede either budget unit.
    input.check()?;
    let version_count = i64::try_from(input.versions.len()).map_err(|_| StorageError::Representation)?;
    let closure_count = i64::try_from(input.closures.len()).map_err(|_| StorageError::Representation)?;
    Plan::new(input, meter, version_count, closure_count)
}

struct Writer<'a, 'b> {
    transaction: &'a StatementTransaction<'b>,
    meter: &'a mut Meter,
    #[cfg(test)]
    hook: &'a mut Hook,
}

impl Writer<'_, '_> {
    async fn request(
        &mut self,
        statement: Statement,
        point: &'static str,
        params: &[StatementParameter<'_>],
        limit: usize,
        maximum: usize,
        probe: bool,
    ) -> Result<Vec<super::StatementRow>, Error> {
        let transaction = self.transaction;
        let meter = &mut *self.meter;
        #[cfg(test)]
        let hook = &mut *self.hook;
        read_request(transaction, meter, statement, params, (limit, maximum, probe), || {
            #[cfg(test)]
            hook.before(point)?;
            #[cfg(not(test))]
            let _ = point;
            Ok(())
        })
        .await
    }

    async fn execute(
        &mut self,
        statement: Statement,
        point: &'static str,
        params: &[StatementParameter<'_>],
    ) -> Result<(), Error> {
        #[cfg(test)]
        self.hook.before(point)?;
        #[cfg(not(test))]
        let _ = point;
        if super::super::super::observed(self.transaction.execute(statement, params)).await? != 1 {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(())
    }

    async fn run(&mut self, input: &Generation, plan: &Plan) -> Result<bool, Error> {
        #[cfg(test)]
        self.hook.before("LockHistory")?;
        super::super::super::observed(self.transaction.batch_execute(Statement::LockHistory)).await?;
        let scope = plan.scope.text()?;
        let rows = self
            .request(
                Statement::ReadAdmissionGeneration,
                "ReadAdmissionGeneration",
                &[&scope, &1_i64],
                1,
                1102,
                false,
            )
            .await?;
        if let Some(row) = rows.first() {
            self.retry(input, scope, row).await
        } else {
            self.fresh(input, plan, scope).await
        }
    }

    async fn retry(&mut self, input: &Generation, scope: &str, header: &super::StatementRow) -> Result<bool, Error> {
        let previous: Option<i64> = header.try_get(1).map_err(|_| StorageError::CorruptHistory)?;
        let label = text(header, 5, 6, 1024)?;
        if positive(header, 0)? != 1 || previous.is_some() || positive(header, 2)? != 1 || label != "unstable" {
            return Err(StorageError::CorruptHistory.into());
        }
        let version_count = usize::try_from(unsigned(header, 3)?).map_err(|_| StorageError::CorruptHistory)?;
        let closure_count = usize::try_from(unsigned(header, 4)?).map_err(|_| StorageError::CorruptHistory)?;
        let version_limit = version_count.checked_add(1).ok_or(StorageError::ReadLimit)?;
        let closure_limit = closure_count.checked_add(1).ok_or(StorageError::ReadLimit)?;
        let version_parameter = i64::try_from(version_limit).map_err(|_| StorageError::ReadLimit)?;
        let closure_parameter = i64::try_from(closure_limit).map_err(|_| StorageError::ReadLimit)?;
        let versions = self
            .request(
                Statement::ReadAdmissionDeltaVersions,
                "ReadAdmissionDeltaVersions",
                &[&scope, &1_i64, &version_parameter],
                version_limit,
                264_411,
                true,
            )
            .await?;
        if versions.len() != version_count {
            return Err(StorageError::CorruptHistory.into());
        }
        let mut decoded_versions = Vec::new();
        self.meter.reserve(&mut decoded_versions, version_count)?;
        for row in &versions {
            if positive(row, 14)? != 1 {
                return Err(StorageError::CorruptHistory.into());
            }
            decoded_versions.push(decode_version(self.meter, row, 0)?);
        }
        let closures = self
            .request(
                Statement::ReadAdmissionDeltaClosures,
                "ReadAdmissionDeltaClosures",
                &[&scope, &1_i64, &closure_parameter],
                closure_limit,
                2143,
                true,
            )
            .await?;
        if closures.len() != closure_count {
            return Err(StorageError::CorruptHistory.into());
        }
        let mut decoded_closures = Vec::new();
        self.meter.reserve(&mut decoded_closures, closure_count)?;
        for row in &closures {
            if positive(row, 7)? != 1 {
                return Err(StorageError::CorruptHistory.into());
            }
            decoded_closures.push(Closure {
                family: family(text(row, 0, 1, 21)?)?,
                key: copy_text(self.meter, text(row, 2, 3, 1024)?)?,
                edition: copy_text(self.meter, text(row, 4, 5, 1024)?)?,
                closes_at: unsigned(row, 6)?,
            });
        }
        if Generation::check_parts(&input.scope, 1, 1, label, &decoded_versions, &decoded_closures).is_err() {
            return Err(StorageError::CorruptHistory.into());
        }
        if decoded_versions != input.versions || decoded_closures != input.closures {
            return Err(Error::AdmissionGenerationConflict);
        }
        Ok(false)
    }

    async fn fresh(&mut self, input: &Generation, plan: &Plan, scope: &str) -> Result<bool, Error> {
        for version in &input.versions {
            let rows = self
                .request(
                    Statement::HasVersion,
                    "HasVersion",
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
        }
        for version in &input.versions {
            i64::try_from(version.announced_at).map_err(|_| StorageError::Representation)?;
            i64::try_from(version.opens_at).map_err(|_| StorageError::Representation)?;
        }
        for closure in &input.closures {
            i64::try_from(closure.closes_at).map_err(|_| StorageError::Representation)?;
        }
        let previous: Option<i64> = None;
        self.execute(
            Statement::InsertAdmissionGeneration,
            "InsertAdmissionGeneration",
            &[
                &scope,
                &1_i64,
                &input.label,
                &previous,
                &1_i64,
                &plan.version_count,
                &plan.closure_count,
            ],
        )
        .await?;
        let mut written_versions = 0usize;
        for index in &plan.version_order {
            let version = &input.versions[*index];
            let payload = version.payload.as_ref();
            // The full conversion pass above proves these signed casts fit before the first insert.
            let announced = version.announced_at.cast_signed();
            let opens = version.opens_at.cast_signed();
            let content = payload.map(|value| value.bytes.as_slice());
            let digest = payload.map(|value| value.digest.as_slice());
            let disclosure = payload.and_then(|value| value.disclosure.as_ref().map(<[u8; 32]>::as_slice));
            self.execute(
                Statement::Insert,
                "Insert",
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
            self.execute(
                Statement::InsertAdmissionVersion,
                "InsertAdmissionVersion",
                &[&scope, &1_i64, &version.family.name(), &version.key, &version.edition],
            )
            .await?;
            written_versions += 1;
        }
        let mut written_closures = 0usize;
        for index in &plan.closure_order {
            let closure = &input.closures[*index];
            let closes = closure.closes_at.cast_signed();
            self.execute(
                Statement::Close,
                "Close",
                &[&closure.family.name(), &closure.key, &closure.edition, &closes],
            )
            .await?;
            self.execute(
                Statement::InsertAdmissionClosure,
                "InsertAdmissionClosure",
                &[&scope, &1_i64, &closure.family.name(), &closure.key, &closure.edition],
            )
            .await?;
            written_closures += 1;
        }
        if written_versions != input.versions.len() || written_closures != input.closures.len() {
            return Err(StorageError::CorruptHistory.into());
        }
        Ok(true)
    }
}
