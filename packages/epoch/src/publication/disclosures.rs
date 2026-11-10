//! Untrusted publication assertions, reconstructed only by the semantic consumer.
//! (´rule:admission:publication-disclosures´)

use super::{Causes, Error, Frame, NumericPolicy, RealizationEvidence, Verifier};
use crate::{ParameterInput, admission, closure, compiler, ledger, package, schedules};
use pn_records::{ActId, burn, constants, numerics};
use std::collections::{BTreeMap, BTreeSet};

pub use nrz_cas::limits::Limits;
/// Existing untrusted numerical evidence vocabulary; replay, not these types, grants authority.
/// (´rule:admission:publication-disclosures´)
pub use nrz_cas::{Exhaustion, Fault, FaultKind, InvalidCode, Location, Rational, enclosure, limits};
/// Public evidence vocabulary reachable without a host-to-graph dependency.
/// These are assertions, not recognized or admitted capabilities.
/// (´rule:admission:publication-disclosures´)
pub use pn_graph::{
    recognition::{PartnerEvidence, RecognitionClause, RecognitionContext},
    title::{TitleEvent, TitleOutcome},
};
/// Records vocabulary and arithmetic limits used by the complete disclosure theory.
/// (´rule:admission:publication-disclosures´)
pub use pn_records as records;

/// Untrusted placement and retained logical-time assertions, never validated metadata.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub position: pn_records::Position,
    pub logical_time: u64,
}

/// Complete settlement assertions, including plain metadata for every handshake leg.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub acts: [ActId; 3],
    pub references: [Option<pn_records::SettlementReferences>; 2],
    pub targets_bind: bool,
    pub partners: PartnerEvidence,
    pub chain: [Option<Metadata>; 3],
    pub times: [Option<pn_records::TimeEvidence>; 3],
    pub item: Option<pn_records::PublicReference>,
    pub prior_owner: Option<String>,
    pub clauses: BTreeMap<RecognitionClause, bool>,
    pub withdrawals: Vec<ActId>,
    pub rescissions: Vec<ActId>,
    pub consumed: BTreeSet<ActId>,
    pub recognized: bool,
}

/// One title boundary's asserted premises, candidates and resulting certificate.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TitleBoundary {
    pub premises: RecognitionContext,
    pub candidates: Vec<Settlement>,
    pub certificate: BTreeMap<pn_records::PublicReference, Option<String>>,
    pub consumed: BTreeSet<ActId>,
}

/// Full title replay assertions, constructible without any graph capability.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Title {
    pub epoch: u64,
    pub certificate: BTreeMap<pn_records::PublicReference, Option<String>>,
    pub consumed: BTreeSet<ActId>,
    pub boundaries: Vec<TitleBoundary>,
    pub events: Vec<TitleEvent>,
}

fn settlement(value: &pn_graph::recognition::SettlementEvidence) -> Settlement {
    Settlement {
        acts: value.acts.clone(),
        references: value.references.clone(),
        targets_bind: value.targets_bind,
        partners: value.partners.clone(),
        chain: value.chain.each_ref().map(|m| {
            m.as_ref().map(|m| Metadata {
                position: m.position,
                logical_time: m.logical_time,
            })
        }),
        times: value.times.clone(),
        item: value.item.clone(),
        prior_owner: value.prior_owner.clone(),
        clauses: value.clauses.clone(),
        withdrawals: value.withdrawals.clone(),
        rescissions: value.rescissions.clone(),
        consumed: value.consumed.clone(),
        recognized: value.recognized,
    }
}

fn title(value: &pn_graph::title::TitleReplay) -> Title {
    Title {
        epoch: value.epoch,
        certificate: value.certificate.clone(),
        consumed: value.consumed.clone(),
        boundaries: value
            .boundaries
            .iter()
            .map(|b| TitleBoundary {
                premises: b.premises.clone(),
                candidates: b.candidates.iter().map(settlement).collect(),
                certificate: b.certificate.clone(),
                consumed: b.consumed.clone(),
            })
            .collect(),
        events: value.events.clone(),
    }
}

/// An asserted recognition result, never an unchecked recognized-marker constructor.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recognition {
    pub basis: burn::RecognitionBasis,
    pub markers: Vec<Marker>,
    pub first_refusal: Option<burn::CandidateRefusal>,
}

/// One marker's asserted complete accepted set and destruction representatives.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    pub identity: burn::Marker,
    pub accepted: BTreeSet<String>,
    pub destructions: BTreeMap<String, burn::BurnRecord>,
}

/// Compiler input assertions retain both interpretation and complete effective edition.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub parameters: ParameterInput,
    pub constants: constants::EditionInput,
}

/// A binding refers to complete causes by ordered act identity, not stored validated acts.
/// Every charge, including historical bindings, is an untrusted price disclosure.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub marker: burn::Marker,
    pub predecessor: burn::Marker,
    pub inputs: Inputs,
    pub price: numerics::PriceInput,
    pub sequence: Vec<ActId>,
}

/// Complete closure assertions with no recognized or admitted capability fields.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Closure {
    pub markers: Recognition,
    pub bindings: Vec<Binding>,
    pub statement: package::ClosureStatement,
    pub partition: Vec<Vec<ActId>>,
    pub final_gates: admission::FinalEvidence,
    pub schedule: schedules::Record,
}

/// A writing vintage assertion. Its price is independently restored before consummation.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Debit {
    pub price: numerics::PriceInput,
    pub boundary: u64,
    pub charged: numerics::BurnAmount,
}

/// Ledger assertions replace every sealed debit by its price and asserted result.
/// Each ledger entry represents one complete act, hence one charged action.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    pub snapshots: Vec<ledger::BurnSnapshot>,
    pub balances: BTreeMap<burn::Address, numerics::BurnAmount>,
    pub counts: BTreeMap<burn::Address, numerics::ActionCount>,
    pub debits: BTreeMap<ActId, Debit>,
}

/// Every compiled section remains an asserted value to compare with independent replay.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    pub title: Title,
    pub ledger: Ledger,
    pub cells: Vec<crate::cells::StandingCell>,
    pub coefficients: BTreeMap<crate::cells::CellIdentity, compiler::CoefficientEvidence>,
    pub recipients: Vec<crate::recipients::ResolvedCell>,
    pub base: crate::base::BaseAllocation,
    pub support: crate::support::StandingSupport,
}

/// One untrusted decoded boundary, with the same sequence/set distinctions as the carrier.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub realization: RealizationEvidence,
    pub burn: burn::BurnInput,
    pub marker_policy: burn::PolicyInput,
    pub marker_history: burn::HistoryInput,
    pub parameters: ParameterInput,
    pub price: numerics::PriceInput,
    pub sequence: Vec<ActId>,
    pub procedure: admission::FinalProcedure,
    pub compiled: Compiled,
    pub closure: Closure,
    pub standing: pn_records::conserved::SolveRecord,
    pub next: schedules::Record,
}

/// Constructible semantic disclosures; bytes, digests and verifier selectors are absent.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    pub causes: Causes,
    pub numeric: NumericPolicy,
    pub frames: Vec<Boundary>,
}

/// The section whose asserted value differs from independent reconstruction.
/// (´rule:admission:publication-disclosures´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Recognition,
    Inputs,
    Sequence,
    Debit,
    Title,
    Ledger,
    Cells,
    Coefficients,
    Recipients,
    Base,
    Support,
}

fn recognition(markers: &burn::RecognizedMarkers) -> Recognition {
    Recognition {
        basis: markers.basis().clone(),
        first_refusal: markers.first_refusal().cloned(),
        markers: markers
            .markers()
            .iter()
            .map(|m| Marker {
                identity: m.identity().clone(),
                accepted: m.accepted().clone(),
                destructions: m.destructions().clone(),
            })
            .collect(),
    }
}

fn binding(binding: &package::EpochBinding) -> Binding {
    Binding {
        marker: binding.marker.clone(),
        predecessor: binding.predecessor.clone(),
        inputs: Inputs {
            parameters: binding.inputs.parameters().clone(),
            constants: binding.inputs.constants().content().clone(),
        },
        price: binding.price.disclosure(),
        sequence: binding.sequence.iter().map(|a| a.id().clone()).collect(),
    }
}

fn disclose_frame(frame: &Frame) -> Boundary {
    let ledger = &frame.compiled.ledger;
    Boundary {
        realization: frame.realization.clone(),
        burn: frame.burn.clone(),
        marker_policy: frame.marker_policy.clone(),
        marker_history: frame.marker_history.clone(),
        parameters: frame.parameters.clone(),
        price: frame.price.clone(),
        sequence: frame.sequence.clone(),
        procedure: frame.procedure.clone(),
        standing: frame.standing.clone(),
        next: frame.next.clone(),
        closure: Closure {
            markers: recognition(&frame.closure.markers),
            bindings: frame.closure.bindings.iter().map(binding).collect(),
            statement: frame.closure.statement.clone(),
            partition: frame.closure.partition.clone(),
            final_gates: frame.closure.final_gates.clone(),
            schedule: frame.closure.schedule.clone(),
        },
        compiled: Compiled {
            title: title(&frame.compiled.title),
            ledger: Ledger {
                snapshots: ledger.snapshots.clone(),
                balances: ledger.balances.clone(),
                counts: ledger.counts.clone(),
                debits: ledger
                    .debits
                    .iter()
                    .map(|(id, debit)| {
                        (
                            id.clone(),
                            Debit {
                                price: debit.price().disclosure(),
                                boundary: debit.boundary(),
                                charged: debit.charged().clone(),
                            },
                        )
                    })
                    .collect(),
            },
            cells: frame.compiled.cells.clone(),
            coefficients: frame.compiled.coefficients.clone(),
            recipients: frame.compiled.recipients.clone(),
            base: frame.compiled.base.clone(),
            support: frame.compiled.support.clone(),
        },
    }
}

/// Fixture projection carries assertions only; restoration still grants authority.
/// (´def:admission:test-support´)
#[cfg(feature = "test-support")]
pub(crate) fn fixture_frame(frame: &Frame) -> Boundary {
    disclose_frame(frame)
}

impl super::AdmittedPackage {
    /// Copy every admitted section into constructible, untrusted semantic disclosures.
    /// (´rule:admission:publication-disclosures´)
    /// Justified: Disclosure grants no authority and preserves independent replay inputs.
    #[must_use]
    pub fn disclosures(&self) -> Disclosure {
        Disclosure {
            causes: self.carrier.causes.clone(),
            numeric: self.carrier.numeric.clone(),
            frames: self.carrier.frames.iter().map(disclose_frame).collect(),
        }
    }
}

fn restore_binding(
    input: &Binding,
    constants: &constants::ConstantsHistory<'_>,
    history: &pn_records::ValidatedHistory,
    numeric: &mut numerics::NumericContext,
    limits: Limits,
    verifier: &impl Verifier,
) -> Result<package::EpochBinding, Error> {
    let parameters = crate::bind_inputs(constants, input.inputs.parameters.clone(), limits)?;
    if parameters.constants().content() != &input.inputs.constants {
        return Err(Error::Disclosure(Section::Inputs));
    }
    let sequence = input
        .sequence
        .iter()
        .map(|id| {
            history
                .acts()
                .iter()
                .find(|act| act.id() == id)
                .cloned()
                .ok_or(Error::Disclosure(Section::Sequence))
        })
        .collect::<Result<_, _>>()?;
    Ok(package::EpochBinding {
        marker: input.marker.clone(),
        predecessor: input.predecessor.clone(),
        inputs: parameters,
        price: super::restore_price(numeric, &input.price, input.inputs.parameters.boundary, verifier)?,
        sequence,
    })
}

fn restore_frame(
    frame: Boundary,
    declarations: &pn_records::ValidatedRecords,
    constants: &constants::ConstantsHistory<'_>,
    history: &pn_records::ValidatedHistory,
    numeric: &NumericPolicy,
    verifier: &impl Verifier,
) -> Result<Frame, Error> {
    let burn = burn::validate_burn(frame.burn.clone())?;
    let policy = constants::bind_marker_policy(declarations, frame.marker_policy.clone(), &burn)?;
    let checked = burn::validate_marker_history(frame.marker_history.clone(), &policy, verifier)?;
    let markers = burn::recognize_markers(&checked);
    if recognition(&markers) != frame.closure.markers {
        return Err(Error::Disclosure(Section::Recognition));
    }
    let mut context = numeric.context()?;
    let bindings = frame
        .closure
        .bindings
        .iter()
        .map(|b| {
            restore_binding(
                b,
                constants,
                history,
                &mut context,
                frame.procedure.arithmetic.clone(),
                verifier,
            )
        })
        .collect::<Result<_, _>>()?;
    let graph = pn_graph::formation::reconstruct_replay(history, verifier)
        .map_err(pn_graph::recognition::RecognitionError::Formation)
        .map_err(|e| Error::Compile(Box::new(compiler::CompileError::Title(e))))?;
    let replayed_title = pn_graph::title::replay_title(&graph, history, verifier, frame.parameters.boundary)
        .map_err(|e| Error::Compile(Box::new(compiler::CompileError::Title(e))))?;
    if title(&replayed_title) != frame.compiled.title {
        return Err(Error::Disclosure(Section::Title));
    }
    let mut debits = BTreeMap::new();
    for (id, debit) in frame.compiled.ledger.debits {
        let price = super::restore_price(&mut context, &debit.price, debit.boundary, verifier)?;
        let restored = context.consummate(&price, numerics::ActionCount(1), debit.boundary)?;
        if restored.charged() != &debit.charged {
            return Err(Error::Disclosure(Section::Debit));
        }
        debits.insert(id, restored);
    }
    Ok(Frame {
        realization: frame.realization,
        burn: frame.burn,
        marker_policy: frame.marker_policy,
        marker_history: frame.marker_history,
        parameters: frame.parameters,
        price: frame.price,
        sequence: frame.sequence,
        procedure: frame.procedure,
        standing: frame.standing,
        next: frame.next,
        closure: closure::ClosureRecord {
            markers,
            bindings,
            statement: frame.closure.statement,
            partition: frame.closure.partition,
            final_gates: frame.closure.final_gates,
            schedule: frame.closure.schedule,
        },
        compiled: compiler::CompiledView {
            title: replayed_title,
            ledger: ledger::FinalLedger {
                snapshots: frame.compiled.ledger.snapshots,
                balances: frame.compiled.ledger.balances,
                counts: frame.compiled.ledger.counts,
                debits,
            },
            cells: frame.compiled.cells,
            coefficients: frame.compiled.coefficients,
            recipients: frame.compiled.recipients,
            base: frame.compiled.base,
            support: frame.compiled.support,
        },
    })
}

/// Restore checked components from disclosures and then replay the complete package.
/// The consumer selects the ridge profile and kernel; a disclosure cannot replace either.
/// (´rule:admission:publication-disclosures´)
/// # Errors
/// Refuses recognition, input, sequence, debit or compiled-section substitutions, and
/// every refusal of full semantic consumption. No partially admitted package escapes.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "publication::disclosures::restore"
    ),
    ret
)]
pub fn restore(disclosure: Disclosure, verifier: &impl Verifier) -> Result<super::AdmittedPackage, Error> {
    if disclosure.frames.iter().any(|frame| !frame.realization.complete()) {
        return Err(Error::Structure("missing realization disclosure"));
    }
    if !verifier.disclosure_profile(&disclosure) {
        return Err(Error::Structure("publication profile"));
    }
    for frame in &disclosure.frames {
        super::charge_profile(&frame.price, frame.parameters.boundary, verifier)?;
        for binding in &frame.closure.bindings {
            super::charge_profile(&binding.price, binding.inputs.parameters.boundary, verifier)?;
        }
        for debit in frame.compiled.ledger.debits.values() {
            super::charge_profile(&debit.price, debit.boundary, verifier)?;
        }
    }
    let empty = pn_records::validate_history(&[], &[])?;
    let declarations = pn_records::validate_record(&[], &empty, &disclosure.causes.declarations)?;
    let constants = constants::bind_constants(&declarations, disclosure.causes.editions.clone())?;
    let names: Vec<_> = disclosure.causes.names.iter().cloned().collect();
    pn_records::validate_history(&disclosure.causes.acts, &names)?;
    let frames = disclosure
        .frames
        .into_iter()
        .map(|frame| {
            let acts: Vec<_> = disclosure
                .causes
                .acts
                .iter()
                .filter(|a| a.finalization_epoch <= frame.parameters.boundary)
                .cloned()
                .collect();
            let history = pn_records::validate_history(&acts, &names)?;
            restore_frame(frame, &declarations, &constants, &history, &disclosure.numeric, verifier)
        })
        .collect::<Result<_, _>>()?;
    super::consume_sections(
        super::Carrier {
            causes: disclosure.causes,
            numeric: disclosure.numeric,
            frames,
        },
        verifier,
        true,
    )
}

pub(super) fn compare(actual: &compiler::CompiledView, asserted: &compiler::CompiledView) -> Option<Section> {
    [
        (actual.title == asserted.title, Section::Title),
        (actual.ledger == asserted.ledger, Section::Ledger),
        (actual.cells == asserted.cells, Section::Cells),
        (actual.coefficients == asserted.coefficients, Section::Coefficients),
        (actual.recipients == asserted.recipients, Section::Recipients),
        (actual.base == asserted.base, Section::Base),
        (actual.support == asserted.support, Section::Support),
    ]
    .into_iter()
    .find_map(|(equal, section)| (!equal).then_some(section))
}

/// Retained act handshake fields, presence-checked but not authenticated.
/// (´[RECORDS-def:acts:authentication-disclosure]´)
pub use pn_records::authentication::{AuthenticationDisclosure, AuthenticationFields, MissingField};
