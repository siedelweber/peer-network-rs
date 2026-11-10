//! Immutable public bytes projected only from an admitted package.
//! (´amend:host:admitted-storage-carrier´)

use crate::storage::{StorageError, Version};
use pn_epoch::publication::disclosures;
use pn_epoch::publication::{AdmittedPackage, disclosures::Limits};
use pn_interchange::{Document, Value};
use pn_records::numerics::NumericContext;
use std::fmt::Write;

mod projection {
    //! Selection coordinates follow typed references, not the set of published declarations.
    //! (´[ROOT-amend:storage:admitted-correspondence]´)
    use super::{CarrierError, DeclarationUse, EpochKey, array, item, key};
    use crate::storage::{self, Family, Payload, Version};
    use crate::storage_payload as encoding;
    use pn_epoch::publication::AdmittedPackage;
    use pn_interchange::{Document, Value};
    use pn_records::{Declaration, DeclarationId};

    struct Uses<'a> {
        package: &'a AdmittedPackage,
        document: &'a Document,
        event: &'a EpochKey,
        rows: Vec<DeclarationUse>,
    }
    impl Uses<'_> {
        fn push(&mut self, selected_at: u64, version: Version) -> Result<(), CarrierError> {
            storage::check(&version).map_err(CarrierError::Storage)?;
            if i64::try_from(selected_at).is_err() {
                return Err(CarrierError::Representation);
            }
            let row = DeclarationUse { selected_at, version };
            if let Some(prior) = self.rows.iter().find(|r| {
                r.selected_at == row.selected_at
                    && r.version.family == row.version.family
                    && r.version.key == row.version.key
                    && r.version.edition == row.version.edition
            }) {
                return if *prior == row {
                    Ok(())
                } else {
                    Err(CarrierError::Correspondence)
                };
            }
            self.rows.push(row);
            Ok(())
        }
        fn declaration(&self, id: &DeclarationId) -> Option<&Declaration> {
            self.package.carrier().causes.declarations.iter().find(|d| d.id == *id)
        }
        fn rule(&mut self, id: &DeclarationId, at: u64) -> Result<(), CarrierError> {
            let Some(d) = self.declaration(id) else { return Ok(()) };
            let encoded_id = encoding::array([
                encoding::text(&id.namespace),
                encoding::text(&id.name),
                encoding::text(&id.edition.to_string()),
            ]);
            let declared = array(item(self.document, 8, &[0])?)?
                .iter()
                .find(|value| array(value).is_ok_and(|fields| fields.first() == Some(&encoded_id)))
                .ok_or(CarrierError::Correspondence)?;
            let version = Version {
                family: Family::Rule,
                key: key(&self.event.scope, &["declaration", &id.namespace, &id.name])?,
                edition: id.edition.to_string(),
                announced_at: d.announced_at,
                opens_at: d.effective_at,
                payload: Some(Payload::rule(&Value::Bytes(declared.to_canonical_bytes().into())).map_err(CarrierError::Storage)?),
            };
            self.push(at, version)
        }
        fn effective(&mut self, namespace: &str, name: &str, at: u64) -> Result<(), CarrierError> {
            let id = self
                .package
                .carrier()
                .causes
                .declarations
                .iter()
                .filter(|d| d.id.namespace == namespace && d.id.name == name && d.effective_at <= at)
                .max_by_key(|d| d.effective_at)
                .ok_or(CarrierError::Correspondence)?
                .id
                .clone();
            self.rule(&id, at)
        }
        fn inputs(&mut self, inputs: &pn_epoch::CompilerInputs) -> Result<(), CarrierError> {
            let p = inputs.parameters();
            self.rule(&p.edition, p.boundary)?;
            for profile in &p.profiles {
                self.rule(&profile.edition, p.boundary)?;
            }
            let d = self.declaration(&p.edition).ok_or(CarrierError::Correspondence)?;
            let version = Version {
                family: Family::Constants,
                key: key(&self.event.scope, &["constants", &d.id.namespace, &d.id.name])?,
                edition: d.id.edition.to_string(),
                announced_at: d.announced_at,
                opens_at: d.effective_at,
                payload: Some(Payload::constants(inputs.constants()).map_err(CarrierError::Storage)?),
            };
            self.push(p.boundary, version)
        }
        fn procedure(&mut self, p: &pn_records::solve::Procedure) -> Result<(), CarrierError> {
            self.rule(&p.edition, p.boundary)
        }
        fn price(&mut self, p: &pn_records::numerics::PriceInput) -> Result<(), CarrierError> {
            if let Some(ridge) = &p.ridge {
                self.procedure(&ridge.procedure)?;
            }
            Ok(())
        }
        fn standing(&mut self, record: &pn_records::conserved::SolveRecord) -> Result<(), CarrierError> {
            for round in &record.rounds {
                for map in round.proposals.iter().chain(std::iter::once(&round.certified)) {
                    self.rule(&map.edition, map.boundary)?;
                }
            }
            Ok(())
        }
        fn schedule(&mut self, record: &pn_epoch::schedules::Record) -> Result<(), CarrierError> {
            for publication in &record.publications {
                self.procedure(&publication.proposal.controller.procedure)?;
            }
            Ok(())
        }
        fn observation(&mut self, family: Family, suffix: &[&str], payload: Payload) -> Result<(), CarrierError> {
            self.push(
                self.event.boundary,
                Version {
                    family,
                    key: key(&self.event.scope, suffix)?,
                    edition: self.event.boundary.to_string(),
                    announced_at: self.event.boundary,
                    opens_at: self.event.boundary,
                    payload: Some(payload),
                },
            )
        }
    }

    pub(super) fn declarations(
        package: &AdmittedPackage,
        document: &Document,
        event: &EpochKey,
    ) -> Result<Vec<DeclarationUse>, CarrierError> {
        let mut uses = Uses {
            package,
            document,
            event,
            rows: Vec::new(),
        };
        for frame in &package.carrier().frames {
            uses.effective("marker", "policy", frame.marker_policy.genesis_at)?;
            uses.effective("deployment", "genesis", frame.marker_policy.genesis_at)?;
            uses.rule(&frame.parameters.edition, frame.parameters.boundary)?;
            for p in &frame.parameters.profiles {
                uses.rule(&p.edition, frame.parameters.boundary)?;
            }
            for binding in &frame.closure.bindings {
                uses.inputs(&binding.inputs)?;
                uses.price(&binding.price.disclosure())?;
            }
            uses.procedure(&frame.procedure.solve)?;
            uses.price(&frame.price)?;
            for debit in frame.compiled.ledger.debits.values() {
                uses.price(&debit.price().disclosure())?;
            }
            uses.rule(&frame.compiled.base.edition, frame.compiled.base.boundary)?;
            uses.standing(&frame.standing)?;
            if let Some(standing) = &frame.closure.final_gates.standing {
                uses.standing(standing)?;
            }
            uses.schedule(&frame.closure.schedule)?;
            uses.schedule(&frame.next)?;
            let b = frame.parameters.boundary.to_string();
            let burn = &frame.burn;
            uses.observation(
                Family::MarkerPolicy,
                &[
                    "policy-observation",
                    &b,
                    &burn.address_space,
                    &burn.edition,
                    &burn.sample_convention,
                ],
                Payload::encoded(
                    Family::MarkerPolicy,
                    encoding::array([encoding::policy(&frame.marker_policy), encoding::publication(burn)]),
                    None,
                )
                .map_err(CarrierError::Storage)?,
            )?;
            uses.observation(
                Family::BurnPublication,
                &["burn", &b, &burn.address_space, &burn.edition, &burn.sample_convention],
                Payload::encoded(Family::BurnPublication, encoding::publication(burn), None).map_err(CarrierError::Storage)?,
            )?;
            let input = encoding::disclosure_parts(&frame.marker_history, &frame.marker_policy, burn);
            let basis = frame.closure.markers.basis();
            let r = [
                &basis.history[..],
                &basis.policy_identity,
                &basis.policy_edition,
                &basis.verifier_profile,
                &basis.burn_publication_edition,
                &basis.sample_convention,
            ];
            let mut lineage = vec!["lineage", &b];
            lineage.extend(r);
            uses.observation(
                Family::Lineage,
                &lineage,
                Payload::encoded(Family::Lineage, input.clone(), None).map_err(CarrierError::Storage)?,
            )?;
            let commitment = storage::digest(storage::DISCLOSURE_RECIPE, &input.to_canonical_bytes());
            let mut recognition = vec!["recognition", &b];
            recognition.extend(r);
            uses.observation(
                Family::UnsettledRecognition,
                &recognition,
                Payload::encoded(
                    Family::UnsettledRecognition,
                    encoding::array([
                        encoding::text(storage::DISCLOSURE_RECIPE),
                        Value::Bytes(commitment.to_vec().into()),
                        input,
                        encoding::recognition(&frame.closure.markers),
                    ]),
                    Some(commitment),
                )
                .map_err(CarrierError::Storage)?,
            )?;
        }
        uses.rows.sort_by(|a, b| {
            (a.version.family, &a.version.key, &a.version.edition, a.selected_at).cmp(&(
                b.version.family,
                &b.version.key,
                &b.version.edition,
                b.selected_at,
            ))
        });
        Ok(uses.rows)
    }
}

/// A complete expected immutable version and the coordinate at which it was selected.
/// (´[ROOT-amend:storage:admitted-correspondence]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclarationUse {
    pub selected_at: u64,
    pub version: Version,
}

/// One complete act's immutable debit identity within its admitted sequence.
/// (´[ROOT-amend:storage:admitted-debits]´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DebitKey {
    pub scope: EpochScope,
    pub act: pn_records::ActId,
}

/// Exact writing vintage and its existing canonical publication item.
/// (´[ROOT-amend:storage:admitted-debits]´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebitVintage {
    pub key: DebitKey,
    pub disclosure: disclosures::Debit,
    pub bytes: Vec<u8>,
}

/// A sequence's structural identity, independent of marker display names.
/// (´[ROOT-amend:storage:admitted-event]´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EpochScope {
    pub history: String,
    pub policy_identity: String,
    pub policy_edition: String,
    pub sequence: String,
}

/// The admitted sequence and terminal marker index identify one storage event.
/// (´[ROOT-amend:storage:admitted-event]´)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EpochKey {
    pub scope: EpochScope,
    pub boundary: u64,
}

/// A carrier refuses representation without changing the admitted package.
/// (´amend:host:admitted-storage-carrier´)
#[derive(Debug)]
pub enum CarrierError {
    Encoding(crate::publication::Error),
    Storage(StorageError),
    Representation,
    Correspondence,
}

/// Immutable admitted-result input; decoding bytes cannot construct this capability.
/// (´amend:host:admitted-storage-carrier´)
/// ```compile_fail
/// fn from_decoded(value: pn_epoch::publication::disclosures::Disclosure,
///     numeric: &mut pn_records::numerics::NumericContext,
///     limits: pn_epoch::publication::disclosures::Limits) {
///     pn_host::storage::AdmittedEpoch::from_package(&value, numeric, limits);
/// }
/// ```
#[derive(Debug)]
pub struct AdmittedEpoch {
    bytes: Vec<u8>,
    event: EpochKey,
    declarations: Vec<DeclarationUse>,
    debits: Vec<DebitVintage>,
    bindings: Vec<disclosures::Binding>,
    markers: Vec<disclosures::Marker>,
}

impl AdmittedEpoch {
    /// Borrow public succession projections under the producing carrier boundary.
    /// (´amend:host:admitted-storage-carrier´)
    /// Justified: Immutable private projection access inherits carrier construction and storage commit recording.
    pub(crate) fn prefix(&self) -> (&[disclosures::Binding], &[disclosures::Marker]) {
        (&self.bindings, &self.markers)
    }

    /// Retain the canonical public package without changing its admission.
    /// (´amend:host:admitted-storage-carrier´)
    /// # Errors
    /// Returns the codec's typed representation or arithmetic refusal.
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::AdmittedEpoch::from_package"
        ),
        ret
    )]
    pub fn from_package(package: &AdmittedPackage, numeric: &mut NumericContext, limits: Limits) -> Result<Self, CarrierError> {
        let result = Self::project(package, numeric, limits);
        if result.is_err() {
            metrics::counter!("host__root__sig__design__storage__refusals").increment(1);
            tracing::event!(tracing::Level::TRACE, outcome = "refusal");
        }
        result
    }

    fn project(package: &AdmittedPackage, numeric: &mut NumericContext, limits: Limits) -> Result<Self, CarrierError> {
        let disclosure = package.disclosures();
        let bytes = crate::publication::encode(&disclosure, numeric, limits).map_err(CarrierError::Encoding)?;
        let marker = &package
            .boundary()
            .candidate()
            .input()
            .causes
            .bindings
            .last()
            .ok_or(CarrierError::Correspondence)?
            .marker;
        let event = event_key(marker);
        if event.boundary == 0 || i64::try_from(event.boundary).is_err() {
            return Err(CarrierError::Representation);
        }
        key(&event.scope, &[])?;
        let document = Document::from_canonical_bytes(&bytes).map_err(|_| CarrierError::Correspondence)?;
        let declarations = projection::declarations(package, &document, &event)?;
        let debits = debit_vintages(&disclosure, &document, &event.scope)?;
        Ok(Self {
            bytes,
            event,
            declarations,
            debits,
            bindings: disclosure
                .frames
                .last()
                .ok_or(CarrierError::Correspondence)?
                .closure
                .bindings
                .clone(),
            markers: disclosure
                .frames
                .last()
                .ok_or(CarrierError::Correspondence)?
                .closure
                .markers
                .markers
                .clone(),
        })
    }

    /// Borrow the retained complete canonical package; this is not a decoding constructor.
    /// (´amend:host:admitted-storage-carrier´)
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::AdmittedEpoch::bytes"
        ),
        ret
    )]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the structural tuple, excluding marker name, position and evidence.
    /// (´[ROOT-amend:storage:admitted-event]´)
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::AdmittedEpoch::event"
        ),
        ret
    )]
    #[must_use]
    pub fn event(&self) -> &EpochKey {
        &self.event
    }

    /// Borrow exact expected payloads, retaining selection and observation times separately.
    /// (´[ROOT-amend:storage:admitted-correspondence]´)
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::AdmittedEpoch::declarations"
        ),
        ret
    )]
    #[must_use]
    pub fn declarations(&self) -> &[DeclarationUse] {
        &self.declarations
    }

    /// Borrow once-per-act writing vintages, not mutable balances or new debits.
    /// (´[ROOT-amend:storage:admitted-debits]´)
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::AdmittedEpoch::debits"
        ),
        ret
    )]
    #[must_use]
    pub fn debits(&self) -> &[DebitVintage] {
        &self.debits
    }

    /// Compare complete retained content separately from structural event equality.
    /// (´[ROOT-amend:storage:admitted-event]´)
    #[tracing::instrument(
        name = "sig:design:storage",
        fields(
            execution_owner = "HOST",
            claim_owner = "ROOT",
            claim_label = "sig:design:storage",
            source_item = "admitted_result::AdmittedEpoch::same_content"
        ),
        ret
    )]
    #[must_use]
    pub fn same_content(&self, other: &Self) -> bool {
        self.event == other.event
            && self.bytes == other.bytes
            && self.declarations == other.declarations
            && self.debits == other.debits
    }
}

pub(crate) fn event_key(marker: &pn_records::burn::Marker) -> EpochKey {
    EpochKey {
        scope: EpochScope {
            history: marker.history.clone(),
            policy_identity: marker.policy_identity.clone(),
            policy_edition: marker.policy_edition.clone(),
            sequence: marker.sequence.clone(),
        },
        boundary: marker.index,
    }
}

fn debit_vintages(
    disclosure: &disclosures::Disclosure,
    document: &Document,
    scope: &EpochScope,
) -> Result<Vec<DebitVintage>, CarrierError> {
    let index = disclosure.frames.len().checked_sub(1).ok_or(CarrierError::Correspondence)?;
    let Value::Map(items) = item(document, 3, &[index, 3])? else {
        return Err(CarrierError::Correspondence);
    };
    let mut result = Vec::new();
    for (act, debit) in &disclosure.frames[index].compiled.ledger.debits {
        key(scope, &[&act.author, &act.sequence.to_string(), &act.family])?;
        let encoded_key = crate::storage_payload::array([
            crate::storage_payload::text(&act.author),
            crate::storage_payload::text(&act.sequence.to_string()),
            crate::storage_payload::text(&act.family),
        ]);
        let value = items
            .iter()
            .find(|(k, _)| **k == encoded_key)
            .ok_or(CarrierError::Correspondence)?
            .1;
        result.push(DebitVintage {
            key: DebitKey {
                scope: scope.clone(),
                act: act.clone(),
            },
            disclosure: debit.clone(),
            bytes: value.to_canonical_bytes(),
        });
    }
    Ok(result)
}

fn key(scope: &EpochScope, suffix: &[&str]) -> Result<String, CarrierError> {
    let parts = [
        &scope.history[..],
        &scope.policy_identity,
        &scope.policy_edition,
        &scope.sequence,
    ];
    let count = parts.len().checked_add(suffix.len()).ok_or(CarrierError::Representation)?;
    let mut output = String::new();
    write!(output, "{count}:").map_err(|_| CarrierError::Representation)?;
    for part in parts.into_iter().chain(suffix.iter().copied()) {
        let length = output
            .len()
            .checked_add(part.len())
            .and_then(|n| n.checked_add(part.len().to_string().len() + 1))
            .ok_or(CarrierError::Representation)?;
        if length > 1024 {
            return Err(CarrierError::Representation);
        }
        write!(output, "{}:{part}", part.len()).map_err(|_| CarrierError::Representation)?;
    }
    Ok(output)
}

pub(crate) fn array(value: &Value) -> Result<&[Value], CarrierError> {
    if let Value::Array(value) = value {
        Ok(value.as_slice())
    } else {
        Err(CarrierError::Correspondence)
    }
}

pub(crate) fn item<'a>(document: &'a Document, section: u64, path: &[usize]) -> Result<&'a Value, CarrierError> {
    let mut value = document.content().get(section).ok_or(CarrierError::Correspondence)?;
    for index in path {
        value = array(value)?.get(*index).ok_or(CarrierError::Correspondence)?;
    }
    Ok(value)
}
