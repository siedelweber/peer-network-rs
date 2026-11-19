//! Borrowed memory-domain collector for the common complete audit.
//! (´[ROOT-amend:storage:tree-audit]´)

use super::super::{MemoryTree, coordinate, unqualified};
use super::{
    AuditFailure, AuditMeter, AuditSite, AuditSource, Collected, RawDebit, RawExpectedDebit, RawGeneration, RawObservation,
    RawResult, RawScope, RawSelection, child_location, descriptor_location, generation_slot_location, generation_source_location,
    placement_location, reference_location, result_index_location, result_location, result_slot_location, scope_location,
    version_location, vintage_location,
};
use crate::admitted_result::position::{Error as PositionError, Representation};
use crate::storage::StorageError;
use pn_interchange::{EncodingError, EncodingUsage, Value};

impl<'a> AuditSource<'a> for MemoryTree<'a> {
    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    fn check_identity(&self, _meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        Ok(())
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    // Justified: One bounded collection pass keeps the five memory domains in their recorded order.
    #[allow(clippy::too_many_lines)]
    fn collect(&'a self, meter: &mut AuditMeter) -> Result<Collected<'a>, AuditFailure> {
        let mut generations = Vec::new();
        meter.reserve(&mut generations, self.generations.len(), AuditSite::NotRead)?;
        for installed in &self.generations {
            meter.visit(generation_source_location(
                &installed.declaration.scope,
                installed.declaration.ordinal,
            ))?;
            generations.push(RawGeneration {
                key: meter.key(
                    &installed.declaration.scope,
                    generation_source_location(&installed.declaration.scope, installed.declaration.ordinal),
                )?,
                declaration: installed.declaration,
                versions: Vec::new(),
                closures: Vec::new(),
            });
        }
        let mut scopes = Vec::new();
        self.scopes.for_each(&mut |scope, pointer| {
            meter.reserve(&mut scopes, 1, scope_location(scope))?;
            meter.visit(scope_location(scope))?;
            scopes.push(RawScope {
                key: meter.key(scope, scope_location(scope))?,
                scope,
                pointer: *pointer,
            });
            Ok(())
        })?;
        let mut results = Vec::new();
        self.results.for_each(&mut |(scope, identity), node| {
            let location = result_location(scope, *identity);
            meter.reserve(&mut results, 1, location)?;
            {
                let location = result_location(scope, *identity);
                meter.visit(location)?;
            }
            let (event_scope, event_identity, parent, depth) = node.input.event();
            if scope != &event_scope || identity != event_identity {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(scope, *identity)));
            }
            let mut selections = Vec::new();
            let location = result_location(scope, *identity);
            meter.reserve(&mut selections, node.references.len(), location)?;
            for reference in &node.references {
                meter.visit(reference_location(scope, *identity, reference.use_))?;
                selections.push(RawSelection {
                    use_: reference.use_,
                    origin: reference.origin,
                });
            }
            let mut selection_order = Vec::new();
            meter.reserve(&mut selection_order, selections.len(), result_location(scope, *identity))?;
            selection_order.extend(0..selections.len());
            selection_order.sort_unstable_by(|&a, &b| coordinate(selections[a].use_).cmp(&coordinate(selections[b].use_)));
            let mut local = Vec::new();
            let location = result_location(scope, *identity);
            meter.reserve(&mut local, node.introductions.len(), location)?;
            for introduction in &node.introductions {
                meter.visit(vintage_location(
                    introduction.vintage,
                    introduction.origin,
                    "pn_epoch_result_debits",
                    None,
                ))?;
                local.push(RawDebit {
                    scope: &introduction.vintage.key.scope,
                    origin: introduction.origin,
                    act: &introduction.vintage.key.act,
                    bytes: &introduction.vintage.bytes,
                });
            }
            let mut observations = Vec::new();
            let location = result_location(scope, *identity);
            meter.reserve(&mut observations, node.observations.len(), location)?;
            for version in &node.observations {
                meter.visit(version_location(
                    version.family,
                    &version.key,
                    &version.edition,
                    "memory.observations",
                ))?;
                observations.push(*version);
            }
            let mut expected_debits = Vec::new();
            meter.reserve(
                &mut expected_debits,
                node.input.debits().len(),
                result_location(scope, *identity),
            )?;
            for debit in node.input.debits() {
                meter.visit(result_location(scope, *identity))?;
                expected_debits.push(RawExpectedDebit {
                    act: &debit.key.act,
                    bytes: &debit.bytes,
                });
            }
            results.push(RawResult {
                key: meter.key(scope, result_location(scope, *identity))?,
                scope,
                identity: *identity,
                parent: parent.copied(),
                depth,
                segment: node.segment,
                package: node.input.bytes(),
                label: node.label,
                generation: node.generation,
                selections,
                selection_order,
                observations,
                local,
                expected_debits,
            });
            Ok(())
        })?;
        Ok(Collected {
            generations,
            scopes,
            results,
        })
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    fn check_shapes(&self, rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        for pair in rows.generations.windows(2) {
            meter.visit(generation_source_location(
                &pair[1].declaration.scope,
                pair[1].declaration.ordinal,
            ))?;
            if pair[0].key == pair[1].key {
                return Err(meter.refused(
                    StorageError::CorruptHistory,
                    generation_source_location(&pair[1].declaration.scope, pair[1].declaration.ordinal),
                ));
            }
        }
        for pair in rows.scopes.windows(2) {
            meter.visit(scope_location(pair[1].scope))?;
            if pair[0].key == pair[1].key {
                return Err(meter.refused(StorageError::CorruptHistory, scope_location(pair[1].scope)));
            }
        }
        for scope in &rows.scopes {
            meter.visit(scope_location(scope.scope))?;
            if scope.key != meter.key(scope.scope, scope_location(scope.scope))? {
                return Err(meter.refused(StorageError::CorruptHistory, scope_location(scope.scope)));
            }
        }
        for pair in rows.results.windows(2) {
            {
                let location = result_location(pair[1].scope, pair[1].identity);
                meter.visit(location)?;
            }
            if (pair[0].key.as_str(), pair[0].identity) == (pair[1].key.as_str(), pair[1].identity) {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(pair[1].scope, pair[1].identity)));
            }
        }
        for row in &rows.results {
            meter.visit(result_location(row.scope, row.identity))?;
            let node = self
                .results
                .get(&(row.scope, row.identity))
                .ok_or_else(|| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
            for pair in node.references.windows(2) {
                let site = reference_location(row.scope, row.identity, pair[1].use_);
                meter.visit(site)?;
                let a = pair[0].use_;
                let b = pair[1].use_;
                if (a.version.family, &a.version.key, &a.version.edition, a.selected_at)
                    >= (b.version.family, &b.version.key, &b.version.edition, b.selected_at)
                {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
        Ok(())
    }

    #[doc = "Justified: Memory index validation inherits the enclosing metered audit operation."]
    fn check_generation_indices(&self, rows: &mut Collected<'a>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        for installed in &self.generations {
            let scope = &installed.declaration.scope;
            let ordinal = installed.declaration.ordinal;
            let site = generation_source_location(scope, ordinal);
            let key = meter.key(scope, site)?;
            meter.visit(site)?;
            let at = rows
                .generations
                .binary_search_by(|row| row.key.cmp(&key))
                .map_err(|_| meter.refused(StorageError::CorruptHistory, site))?;
            let row = &mut rows.generations[at];
            if installed.versions.len() != row.declaration.versions.len()
                || installed.closures.len() != row.declaration.closures.len()
            {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            meter.reserve(&mut row.versions, installed.versions.len(), site)?;
            for (position, &index) in installed.versions.iter().enumerate() {
                let slot_site = generation_slot_location(scope, ordinal, "memory.generation_versions", position);
                meter.visit(slot_site)?;
                if index != position {
                    return Err(meter.refused(StorageError::CorruptHistory, slot_site));
                }
                row.versions.push(&row.declaration.versions[index]);
            }
            meter.reserve(&mut row.closures, installed.closures.len(), site)?;
            for (position, &index) in installed.closures.iter().enumerate() {
                let slot_site = generation_slot_location(scope, ordinal, "memory.generation_closures", position);
                meter.visit(slot_site)?;
                if index != position {
                    return Err(meter.refused(StorageError::CorruptHistory, slot_site));
                }
                row.closures.push(&row.declaration.closures[index]);
            }
        }
        Ok(())
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    fn check_forest_joins(&self, rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        for scope in &rows.scopes {
            meter.visit(scope_location(scope.scope))?;
            meter.visit(scope_location(scope.scope))?;
            let root = rows
                .results
                .binary_search_by(|row| (&row.key, row.identity).cmp(&(&scope.key, scope.pointer)))
                .ok()
                .and_then(|index| rows.results.get(index));
            if root.is_none_or(|row| row.parent.is_some()) {
                return Err(meter.refused(StorageError::CorruptHistory, scope_location(scope.scope)));
            }
        }
        Ok(())
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    fn check_reference_index(&self, rows: &Collected<'_>, meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        for row in &rows.results {
            meter.visit(result_location(row.scope, row.identity))?;
            let node = self
                .results
                .get(&(row.scope, row.identity))
                .ok_or_else(|| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
            if node.reference_index.len() != node.references.len() {
                return Err(meter.refused(
                    StorageError::CorruptHistory,
                    result_index_location(row.scope, row.identity, "memory.reference_index"),
                ));
            }
            let mut seen = Vec::new();
            let location = result_location(row.scope, row.identity);
            meter.reserve(&mut seen, node.references.len(), location)?;
            seen.resize(node.references.len(), false);
            let mut previous = None;
            for (position, &slot) in node.reference_index.iter().enumerate() {
                let site = result_slot_location(row.scope, row.identity, "memory.reference_index", position);
                meter.visit(site)?;
                let Some(reference) = node.references.get(slot) else {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                };
                if seen[slot] || previous.is_some_and(|prior| prior >= coordinate(reference.use_)) {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
                seen[slot] = true;
                previous = Some(coordinate(reference.use_));
            }
        }
        Ok(())
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    // Justified: Descriptor and auxiliary index checks share one ordered physical-consistency phase.
    #[allow(clippy::too_many_lines)]
    fn check_segments(
        &self,
        rows: &Collected<'_>,
        parents: &[Option<usize>],
        children: &[Vec<usize>],
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure> {
        let mut segment_order = Vec::new();
        meter.reserve(&mut segment_order, rows.results.len(), AuditSite::NotRead)?;
        segment_order.extend(0..rows.results.len());
        segment_order.sort_unstable_by_key(|&at| {
            let row = &rows.results[at];
            (&row.key, row.segment, row.depth, row.identity)
        });
        let mut descriptor_count = 0usize;
        self.segments.for_each(&mut |(scope, segment), descriptor| {
            let site = descriptor_location(scope, *segment);
            meter.visit(site)?;
            descriptor_count = descriptor_count
                .checked_add(1)
                .ok_or_else(|| meter.refused(StorageError::ReadLimit, site))?;
            let key = meter.key(scope, site)?;
            meter.visit(site)?;
            let first_index = segment_order.partition_point(|&at| {
                let row = &rows.results[at];
                (row.key.as_str(), row.segment) < (key.as_str(), *segment)
            });
            meter.visit(site)?;
            let last_index = segment_order.partition_point(|&at| {
                let row = &rows.results[at];
                (row.key.as_str(), row.segment) <= (key.as_str(), *segment)
            });
            let group = &segment_order[first_index..last_index];
            let Some(&first_at) = group.first() else {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            };
            let first = &rows.results[first_at];
            if descriptor.first != first.identity
                || *segment != first.identity
                || descriptor.start != first.depth
                || descriptor.fork != first.parent
                || descriptor.cutoff != first.depth - 1
            {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            let actual_parent_segment = parents[first_at].map(|at| rows.results[at].segment);
            if descriptor.parent_segment != actual_parent_segment {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            for pair in group.windows(2) {
                let before = &rows.results[pair[0]];
                let after = &rows.results[pair[1]];
                {
                    let location = result_location(after.scope, after.identity);
                    meter.visit(location)?;
                }
                if before.depth.checked_add(1) != Some(after.depth) || after.parent != Some(before.identity) {
                    return Err(meter.refused(StorageError::CorruptHistory, result_location(after.scope, after.identity)));
                }
            }
            Ok(())
        })?;
        if descriptor_count > rows.results.len() {
            return Err(meter.refused(StorageError::CorruptHistory, AuditSite::NotRead));
        }
        for row in &rows.results {
            {
                let location = result_location(row.scope, row.identity);
                meter.visit(location)?;
            }
            meter.visit(result_location(row.scope, row.identity))?;
            if self.segments.get(&(row.scope, row.segment)).is_none() {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
            }
        }
        let mut placement_count = 0usize;
        self.placements.for_each(&mut |(scope, segment, depth), identity| {
            let site = placement_location(scope, *segment, *depth, "memory.placements");
            meter.visit(site)?;
            placement_count = placement_count
                .checked_add(1)
                .ok_or_else(|| meter.refused(StorageError::ReadLimit, site))?;
            let key = meter.key(scope, site)?;
            meter.visit(site)?;
            let row = segment_order
                .binary_search_by(|&at| {
                    let row = &rows.results[at];
                    (row.key.as_str(), row.segment, row.depth).cmp(&(key.as_str(), *segment, *depth))
                })
                .ok()
                .map(|at| &rows.results[segment_order[at]]);
            if row.is_none_or(|row| row.identity != *identity) {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            Ok(())
        })?;
        if placement_count != rows.results.len() {
            for row in &rows.results {
                let site = result_location(row.scope, row.identity);
                meter
                    .visit(site)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, AuditSite::NotRead))?;
                if self.placements.get(&(row.scope, row.segment, row.depth)).is_none() {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
        let mut child_count = 0usize;
        self.direct_children.for_each(&mut |(scope, parent, identity), ()| {
            let site = child_location(scope, *parent, *identity);
            meter.visit(site)?;
            child_count = child_count
                .checked_add(1)
                .ok_or_else(|| meter.refused(StorageError::ReadLimit, site))?;
            let key = meter.key(scope, site)?;
            meter.visit(site)?;
            if match rows
                .results
                .binary_search_by(|row| (row.key.as_str(), row.identity).cmp(&(key.as_str(), *identity)))
            {
                Ok(at) => rows.results[at].parent != *parent,
                Err(_) => true,
            } {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            Ok(())
        })?;
        if child_count != rows.results.len() {
            for row in &rows.results {
                let site = result_location(row.scope, row.identity);
                meter
                    .visit(site)
                    .map_err(|_| meter.refused(StorageError::CorruptHistory, AuditSite::NotRead))?;
                if self.direct_children.get(&(row.scope, row.parent, row.identity)).is_none() {
                    return Err(meter.refused(StorageError::CorruptHistory, site));
                }
            }
        }
        self.children.for_each(&mut |(scope, parent), identity| {
            let site = result_index_location(scope, *parent, "memory.first_children");
            meter.visit(site)?;
            let key = meter.key(scope, site)?;
            meter.visit(site)?;
            let row = rows
                .results
                .binary_search_by(|row| (row.key.as_str(), row.identity).cmp(&(key.as_str(), *identity)))
                .ok()
                .map(|at| &rows.results[at])
                .filter(|row| row.parent == Some(*parent));
            if row.is_none_or(|row| row.segment == row.identity) {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            Ok(())
        })?;
        for (at, parent) in rows.results.iter().enumerate() {
            {
                let location = result_location(parent.scope, parent.identity);
                meter.visit(location)?;
            }
            let mut continuing = None;
            for &child_at in &children[at] {
                let child = &rows.results[child_at];
                {
                    let location = result_location(child.scope, child.identity);
                    meter.visit(location)?;
                }
                if child.scope == parent.scope
                    && child.parent == Some(parent.identity)
                    && child.segment == parent.segment
                    && continuing.replace(child.identity).is_some()
                {
                    return Err(meter.refused(StorageError::CorruptHistory, result_location(child.scope, child.identity)));
                }
            }
            meter.visit(result_index_location(parent.scope, parent.identity, "memory.first_children"))?;
            if self.children.get(&(parent.scope, parent.identity)).copied() != continuing {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(parent.scope, parent.identity)));
            }
        }
        self.introductions.for_each(&mut |(scope, segment, depth), identity| {
            let site = placement_location(scope, *segment, *depth, "memory.introductions");
            meter.visit(site)?;
            let key = meter.key(scope, site)?;
            meter.visit(site)?;
            let row = rows
                .results
                .binary_search_by(|row| (row.key.as_str(), row.identity).cmp(&(key.as_str(), *identity)))
                .ok()
                .map(|at| &rows.results[at])
                .filter(|row| row.segment == *segment && row.depth == *depth);
            if row.is_none_or(|row| row.local.is_empty()) {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            Ok(())
        })?;
        for row in &rows.results {
            {
                let location = result_location(row.scope, row.identity);
                meter.visit(location)?;
            }
            meter.visit(placement_location(row.scope, row.segment, row.depth, "memory.introductions"))?;
            if self.introductions.get(&(row.scope, row.segment, row.depth)).copied()
                != (!row.local.is_empty()).then_some(row.identity)
            {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
            }
        }
        Ok(())
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    // Justified: Package, reference, origin and vintage checks keep their semantic refusal order together.
    #[allow(clippy::too_many_lines)]
    fn check_content(
        &self,
        row: &RawResult<'_>,
        parent: Option<&RawResult<'_>>,
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure> {
        meter.visit(result_location(row.scope, row.identity))?;
        let node = self
            .results
            .get(&(row.scope, row.identity))
            .ok_or_else(|| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
        let mut bytes = Vec::new();
        let reserve_location = result_location(row.scope, row.identity);
        meter.reserve(&mut bytes, row.package.len(), reserve_location)?;
        for (slot, chunk) in node.chunks.iter().enumerate() {
            let location = result_slot_location(row.scope, row.identity, "pn_epoch_package_chunks", slot);
            meter.visit(location)?;
            if chunk.is_empty() || chunk.len() > super::super::super::MAX_PACKAGE {
                return Err(meter.refused(StorageError::CorruptHistory, location));
            }
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > row.package.len())
            {
                return Err(meter.refused(StorageError::CorruptHistory, location));
            }
            bytes.extend_from_slice(chunk);
        }
        if bytes != row.package || node.references.len() != node.input.declarations().len() {
            return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
        }
        for (reference, expected) in node.references.iter().zip(node.input.declarations()) {
            let reference_site = reference_location(row.scope, row.identity, reference.use_);
            meter.visit(reference_site)?;
            if reference.use_ != expected {
                return Err(meter.refused(StorageError::CorruptHistory, reference_site));
            }
            if unqualified(expected.version.family) {
                meter.visit(reference_site)?;
                let generation = self
                    .generations
                    .binary_search_by(|g| g.declaration.scope.cmp(row.scope))
                    .ok()
                    .map(|at| &self.generations[at])
                    .ok_or_else(|| meter.refused(StorageError::CorruptHistory, reference_site))?;
                match MemoryTree::selected_with_probes(generation, expected, &mut meter.core, true) {
                    Ok(()) => {}
                    Err(super::super::Error::Storage(StorageError::ReadLimit)) => {
                        return Err(meter.refused(StorageError::ReadLimit, reference_site));
                    }
                    Err(_) => return Err(meter.refused(StorageError::CorruptHistory, reference_site)),
                }
            }
        }
        for introduction in &node.introductions {
            let introduction_site = vintage_location(introduction.vintage, introduction.origin, "pn_epoch_result_debits", None);
            meter.visit(introduction_site)?;
            if !introduction.member {
                return Err(meter.refused(StorageError::CorruptHistory, introduction_site));
            }
            let mut debit_bytes = Vec::new();
            meter.reserve(&mut debit_bytes, introduction.vintage.bytes.len(), introduction_site)?;
            for (slot, chunk) in introduction.chunks.iter().enumerate() {
                let chunk_site = vintage_location(introduction.vintage, introduction.origin, "pn_epoch_debit_chunks", Some(slot));
                meter.visit(chunk_site)?;
                if chunk.is_empty() || chunk.len() > super::super::super::MAX_PACKAGE {
                    return Err(meter.refused(StorageError::CorruptHistory, chunk_site));
                }
                if debit_bytes
                    .len()
                    .checked_add(chunk.len())
                    .is_none_or(|length| length > introduction.vintage.bytes.len())
                {
                    return Err(meter.refused(StorageError::CorruptHistory, chunk_site));
                }
                debit_bytes.extend_from_slice(chunk);
            }
            if debit_bytes != introduction.vintage.bytes {
                return Err(meter.refused(StorageError::CorruptHistory, introduction_site));
            }
        }
        if let Some(parent) = parent {
            meter.visit(result_location(row.scope, row.identity))?;
            let prior = self
                .results
                .get(&(parent.scope, parent.identity))
                .ok_or_else(|| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
            if !node.input.extends(prior.input) || !node.input.same_context(prior.input) {
                return Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)));
            }
        }
        Ok(())
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    fn context(&self, row: &RawResult<'_>, meter: &mut AuditMeter) -> Result<Value, AuditFailure> {
        meter.visit(result_location(row.scope, row.identity))?;
        let node = self
            .results
            .get(&(row.scope, row.identity))
            .ok_or_else(|| meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity)))?;
        let mut usage = EncodingUsage::default();
        let mut refusal = None;
        let value = node.input.audit_context(meter.core.limit.bytes, &mut usage, &mut |bytes| {
            let location = result_location(row.scope, row.identity);
            match meter.allocation(bytes, location) {
                Ok(_) => Ok(()),
                Err(error) => {
                    refusal = Some(error);
                    Err(())
                }
            }
        });
        if let Some(error) = refusal {
            return Err(error);
        }
        match value {
            Ok(value) => Ok(value),
            Err(PositionError::Representation(Representation::Encoding(EncodingError::Allocation))) => {
                Err(meter.allocated(result_location(row.scope, row.identity)))
            }
            Err(_) => Err(meter.refused(StorageError::CorruptHistory, result_location(row.scope, row.identity))),
        }
    }

    #[doc = "Justified: Memory observation enumeration inherits the enclosing metered audit operation."]
    fn collect_observations(&'a self, meter: &mut AuditMeter) -> Result<Vec<RawObservation<'a>>, AuditFailure> {
        let mut observed = Vec::new();
        self.observations.for_each(&mut |(family, key, edition), version| {
            let site = version_location(*family, key, edition, "memory.observations");
            meter.reserve(&mut observed, 1, site)?;
            meter.visit(site)?;
            observed.push(RawObservation {
                family: *family,
                key,
                edition,
                version,
            });
            Ok(())
        })?;
        Ok(observed)
    }

    #[doc = "Justified: Memory audit adapter work inherits the enclosing metered audit operation."]
    fn check_enumeration(
        &self,
        rows: &Collected<'_>,
        children: &[Vec<usize>],
        meter: &mut AuditMeter,
    ) -> Result<(), AuditFailure> {
        for row in &rows.results {
            let site = result_location(row.scope, row.identity);
            meter.visit(site)?;
            if self.scopes.get(&row.scope).is_none() {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
            meter.visit(site)?;
            if self.results.get(&(row.scope, row.identity)).is_none() {
                return Err(meter.refused(StorageError::CorruptHistory, site));
            }
        }
        self.audit_pages(rows, children, meter)?;
        Ok(())
    }
}

impl MemoryTree<'_> {
    fn audit_pages(&self, rows: &Collected<'_>, children: &[Vec<usize>], meter: &mut AuditMeter) -> Result<(), AuditFailure> {
        for scope in &rows.scopes {
            meter.visit(scope_location(scope.scope))?;
            let first = rows.results.partition_point(|row| row.key < scope.key);
            meter.visit(scope_location(scope.scope))?;
            let last = rows.results.partition_point(|row| row.key <= scope.key);
            let mut after = None;
            for expected in &rows.results[first..last] {
                let location = result_location(expected.scope, expected.identity);
                meter.visit(location)?;
                let next = self.results.seek(&(scope.scope, after.unwrap_or([0; 32])), after.is_some());
                if next.is_none_or(|((found_scope, identity), _)| *found_scope != scope.scope || *identity != expected.identity) {
                    return Err(meter.refused(
                        StorageError::CorruptHistory,
                        result_location(expected.scope, expected.identity),
                    ));
                }
                after = Some(expected.identity);
            }
            meter.visit(scope_location(scope.scope))?;
            if self
                .results
                .seek(&(scope.scope, after.unwrap_or([0; 32])), after.is_some())
                .is_some_and(|((found_scope, _), _)| *found_scope == scope.scope)
            {
                return Err(meter.refused(StorageError::CorruptHistory, scope_location(scope.scope)));
            }

            let mut root_after = None;
            for expected in rows.results[first..last].iter().filter(|row| row.parent.is_none()) {
                let location = result_location(expected.scope, expected.identity);
                meter.visit(location)?;
                let next = self
                    .direct_children
                    .seek(&(scope.scope, None, root_after.unwrap_or([0; 32])), root_after.is_some());
                if next.is_none_or(|((found_scope, parent, identity), ())| {
                    *found_scope != scope.scope || parent.is_some() || *identity != expected.identity
                }) {
                    return Err(meter.refused(
                        StorageError::CorruptHistory,
                        result_location(expected.scope, expected.identity),
                    ));
                }
                root_after = Some(expected.identity);
            }
            meter.visit(scope_location(scope.scope))?;
            if self
                .direct_children
                .seek(&(scope.scope, None, root_after.unwrap_or([0; 32])), root_after.is_some())
                .is_some_and(|((found_scope, parent, _), ())| *found_scope == scope.scope && parent.is_none())
            {
                return Err(meter.refused(StorageError::CorruptHistory, scope_location(scope.scope)));
            }

            for (offset, candidate) in rows.results[first..last].iter().enumerate() {
                let location = result_location(candidate.scope, candidate.identity);
                meter.visit(location)?;
                let found = self
                    .direct_children
                    .seek(&(scope.scope, Some(candidate.identity), [0; 32]), false)
                    .is_some_and(|((found_scope, parent, _), ())| {
                        *found_scope == scope.scope && *parent == Some(candidate.identity)
                    });
                let expected = !children[first + offset].is_empty();
                if found != expected {
                    return Err(meter.refused(
                        StorageError::CorruptHistory,
                        result_location(candidate.scope, candidate.identity),
                    ));
                }
            }
        }
        Ok(())
    }
}
