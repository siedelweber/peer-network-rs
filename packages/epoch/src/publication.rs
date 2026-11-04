//! Complete semantic publication and independent consumption, without a byte codec.
//! (´rule:admission:semantic-carrier´)

use crate::{ParameterInput, admission, closure, compiler, package, schedules, solve};
use pn_graph::numeric::ridge;
use pn_records::{ActId, CandidateAct, Declaration, PublicReference, burn, constants, numerics};
use std::collections::{BTreeMap, BTreeSet};

pub mod disclosures;

/// Opening kind required by the publication consumer's removal verifier.
/// (´rule:admission:publication-disclosures´)
pub use pn_graph::registration::OpeningKind;
/// Approval and removal contract implementable through the epoch consumer surface.
/// (´rule:admission:publication-disclosures´)
pub use pn_graph::registration::RegistrationVerifier;

/// External profile checks remain explicit; no digest or restored trust bit supplies them.
/// (´rule:admission:semantic-carrier´)
pub trait Verifier:
    burn::PublicVerifier + package::CandidateVerifier + package::ClosureVerifier + RegistrationVerifier + solve::ProcedureVerifier
{
    /// Check the declared publication procedure and resource settings before replay.
    fn publication_profile(&self, carrier: &Carrier) -> bool;
    /// Check untrusted declared limits and realization evidence before reconstruction.
    fn disclosure_profile(&self, disclosure: &disclosures::Disclosure) -> bool;
}

/// Complete public causes. Act presentation is a set; each frame's sequence is ordered.
/// Declaration payloads and marker disclosures are retained, not replaced by identities.
/// (´rule:admission:semantic-carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Causes {
    pub acts: Vec<CandidateAct>,
    pub names: BTreeSet<PublicReference>,
    pub declarations: Vec<Declaration>,
    pub editions: Vec<constants::EditionInput>,
}

/// Public realization audit disclosures, retained without becoming standing inputs.
/// The declared publication verifier checks their edition and substantive evidence.
/// (´rule:admission:semantic-carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealizationEvidence {
    pub edition: String,
    pub provenance: Vec<u8>,
    pub capacity_bound: Vec<u8>,
    pub dimensioned_unit_cost: Vec<u8>,
    pub recording_event_costs: Vec<u8>,
    pub settlement_and_finality: Vec<u8>,
    pub operator: OperatorEvidence,
}

/// An operator bound and proof, or an explicit absence statement with its explanation.
/// (´rule:admission:semantic-carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorEvidence {
    Bound { bound: Vec<u8>, proof: Vec<u8> },
    Absent { statement: Vec<u8>, explanation: Vec<u8> },
}

impl RealizationEvidence {
    fn complete(&self) -> bool {
        let (first, second) = match &self.operator {
            OperatorEvidence::Bound { bound, proof } => (bound, proof),
            OperatorEvidence::Absent { statement, explanation } => (statement, explanation),
        };
        !self.edition.is_empty()
            && [
                &self.provenance,
                &self.capacity_bound,
                &self.dimensioned_unit_cost,
                &self.recording_event_costs,
                &self.settlement_and_finality,
                first,
                second,
            ]
            .iter()
            .all(|bytes| !bytes.is_empty())
    }
}

/// One complete boundary's assertions and replay attachments, never authority by itself.
/// Compiled view carries title/recognition, ledger, cells, recipients, base and emission.
/// Closure carries final gates, standing, all attempted rungs and transport attachments.
/// The next schedule includes this completed boundary's proposal and delivered led value.
/// (´rule:admission:semantic-carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub realization: RealizationEvidence,
    pub burn: burn::BurnInput,
    pub marker_policy: burn::PolicyInput,
    pub marker_history: burn::HistoryInput,
    pub parameters: ParameterInput,
    pub price: numerics::PriceInput,
    pub sequence: Vec<ActId>,
    pub procedure: admission::FinalProcedure,
    pub compiled: compiler::CompiledView,
    pub closure: closure::ClosureRecord,
    pub standing: pn_records::conserved::SolveRecord,
    pub next: schedules::Record,
}

/// Explicit bounded numeric context, retained separately from displayed values.
/// (´rule:admission:semantic-carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumericPolicy {
    pub arithmetic: nrz_cas::limits::Limits,
    pub comparison_attempts: u32,
    pub comparison_work: u64,
}

impl NumericPolicy {
    fn context(&self) -> Result<numerics::NumericContext, Error> {
        Ok(numerics::NumericContext::new(
            self.arithmetic.clone(),
            numerics::ComparisonLimits::new(self.comparison_attempts, self.comparison_work),
        )?)
    }
}

/// Untrusted complete immutable-field theory before verification; encoding is not defined.
/// Frames retain boundary order and complete prefixes; no previous-standing input exists.
/// (´rule:admission:semantic-carrier´)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carrier {
    pub causes: Causes,
    pub numeric: NumericPolicy,
    pub frames: Vec<Frame>,
}

/// Inhabited only after independent restoration has passed closure and final admission.
/// No mutable field escapes, and this carrier does not perform persistence or publication.
/// (´rule:admission:semantic-carrier´)
#[derive(Debug)]
pub struct AdmittedPackage {
    carrier: Carrier,
    closed: closure::ClosedBoundary,
}

/// Missing causes, changed evidence and operational failures remain distinguishable.
/// (´rule:admission:semantic-carrier´)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("publication disclosure differs: {0:?}")]
    Disclosure(disclosures::Section),
    #[error("publication structure: {0}")]
    Structure(&'static str),
    #[error("publication records: {0}")]
    Records(#[from] pn_records::ValidationError),
    #[error("publication marker disclosure: {0}")]
    Burn(#[from] burn::BurnError),
    #[error("publication constants: {0}")]
    Constants(#[from] constants::ConstantsError),
    #[error("publication inputs: {0}")]
    Inputs(#[from] crate::InputError),
    #[error("publication charge: {0}")]
    Numeric(#[from] numerics::NumericError),
    #[error("publication candidate: {0}")]
    Candidate(#[from] package::PackageError),
    #[error("publication compilation: {0}")]
    Compile(#[source] Box<compiler::CompileError>),
    #[error("publication procedure: {0}")]
    Procedure(#[from] solve::ProcedureError),
    #[error("publication standing: {0}")]
    Standing(#[source] Box<crate::conserved::Error>),
    #[error("publication closure: {0}")]
    Closure(#[from] closure::ClosureError),
    #[error("publication schedule: {0}")]
    Schedule(#[from] schedules::Error),
    #[error("publication declaration: {0}")]
    Declaration(#[from] admission::DeclarationError),
    #[error("publication ridge: {0}")]
    Ridge(#[from] ridge::Error),
}

fn initial(carrier: &Carrier) -> Result<schedules::CheckedSchedule, Error> {
    let frame = carrier.frames.first().ok_or(Error::Structure("empty boundary sequence"))?;
    let declaration =
        admission::declare_schedule(frame.closure.schedule.declaration.clone(), carrier.numeric.arithmetic.clone())?;
    let checked = frame
        .price
        .ridge
        .as_deref()
        .map(|e| ridge::replay(&e.procedure, &e.input, &e.record))
        .transpose()?;
    Ok(schedules::replay(
        &declaration,
        &[],
        checked.as_ref(),
        carrier.numeric.arithmetic.clone(),
        &frame.closure.schedule,
    )?)
}

fn next(
    carrier: &Carrier,
    states: &[compiler::CompiledState],
    verifier: &impl Verifier,
) -> Result<schedules::CheckedSchedule, Error> {
    let count = states.len();
    let frame = &carrier.frames[count - 1];
    if frame.next.publications.len() != count {
        return Err(Error::Structure("missing completed announcement"));
    }
    if frame.next.declaration != frame.closure.schedule.declaration
        || frame.next.initial != frame.closure.schedule.initial
        || frame.next.publications.get(..count - 1) != Some(frame.closure.schedule.publications.as_slice())
    {
        return Err(Error::Structure("changed announcement prefix"));
    }
    let declaration = admission::declare_schedule(frame.next.declaration.clone(), carrier.numeric.arithmetic.clone())?;
    let checked = carrier.frames[0]
        .price
        .ridge
        .as_deref()
        .map(|e| ridge::replay(&e.procedure, &e.input, &e.record))
        .transpose()?;
    let bound: Vec<_> = states
        .iter()
        .zip(&carrier.frames)
        .map(|(state, f)| solve::bind_procedure(state, f.procedure.solve.clone(), verifier, f.procedure.arithmetic.clone()))
        .collect::<Result<_, _>>()?;
    let boundaries: Vec<_> = bound
        .iter()
        .zip(&frame.next.publications)
        .map(|(completed, p)| schedules::Boundary {
            completed,
            search: &p.proposal.search,
            announced_at: p.announced_at,
            effective_at: p.effective.boundary,
            policy_floor: Some(p.effective.policy_floor.clone()),
        })
        .collect();
    Ok(schedules::replay(
        &declaration,
        &boundaries,
        checked.as_ref(),
        carrier.numeric.arithmetic.clone(),
        &frame.next,
    )?)
}

struct RebuiltFrame {
    markers: burn::RecognizedMarkers,
    input: crate::CompilerInputs,
    price: numerics::ChargedPrice,
    history: pn_records::ValidatedHistory,
    binding: package::EpochBinding,
}

fn rebuild(
    carrier: &Carrier,
    frame: &Frame,
    offset: usize,
    declarations: &pn_records::ValidatedRecords,
    constants: &constants::ConstantsHistory<'_>,
    verifier: &impl Verifier,
) -> Result<RebuiltFrame, Error> {
    let burn = burn::validate_burn(frame.burn.clone())?;
    let policy = constants::bind_marker_policy(declarations, frame.marker_policy.clone(), &burn)?;
    let history = burn::validate_marker_history(frame.marker_history.clone(), &policy, verifier)?;
    let markers = burn::recognize_markers(&history);
    let input = crate::bind_inputs(constants, frame.parameters.clone(), frame.procedure.arithmetic.clone())?;
    if frame.price.floor != input.constants().content().floor || frame.price.numeraire != input.parameters().numeraire {
        return Err(Error::Structure("mixed charge declaration"));
    }
    let price = carrier
        .numeric
        .context()?
        .restore_charged_price(&frame.price, &ridge::ChargeReplay)?;
    let names: Vec<_> = carrier.causes.names.iter().cloned().collect();
    let boundary = frame.parameters.boundary;
    let acts: Vec<_> = carrier
        .causes
        .acts
        .iter()
        .filter(|a| a.finalization_epoch <= boundary)
        .cloned()
        .collect();
    let history = pn_records::validate_history(&acts, &names)?;
    let by_id: BTreeMap<_, _> = history.acts().iter().map(|a| (a.id(), a)).collect();
    let sequence = frame
        .sequence
        .iter()
        .map(|id| {
            by_id
                .get(id)
                .map(|a| (*a).clone())
                .ok_or(Error::Structure("omitted sequence cause"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let marker = markers
        .markers()
        .get(offset + 1)
        .ok_or(Error::Structure("missing recognized marker"))?;
    let binding = package::EpochBinding {
        marker: marker.identity().clone(),
        predecessor: markers.markers()[offset].identity().clone(),
        inputs: input.clone(),
        price: price.clone(),
        sequence,
    };
    Ok(RebuiltFrame {
        markers,
        input,
        price,
        history,
        binding,
    })
}

fn standing(state: &compiler::CompiledState, frame: &Frame, verifier: &impl Verifier) -> Result<(), Error> {
    let bound = solve::bind_procedure(
        state,
        frame.procedure.solve.clone(),
        verifier,
        frame.procedure.arithmetic.clone(),
    )?;
    crate::conserved::replay(&bound, &frame.standing).map_err(|error| Error::Standing(Box::new(error)))?;
    if frame
        .closure
        .final_gates
        .standing
        .as_ref()
        .is_some_and(|record| record != &frame.standing)
    {
        return Err(Error::Structure("mixed standing and admission"));
    }
    Ok(())
}

/// Rebuild every checked boundary from complete public causes. Every restored charge is
/// reverified under graph `ChargeReplay` before candidate compilation; all output sections
/// are compared with independent derivation, not trusted from a digest or prior carrier.
/// (´rule:admission:semantic-carrier´)
/// # Errors
/// Refuses incomplete or mixed causes, changed sections, invalid disclosures, any final
/// gate refusal, unresolved comparison or exhausted declared numerical operation.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "publication::consume"
    ),
    ret
)]
pub fn consume(carrier: Carrier, verifier: &impl Verifier) -> Result<AdmittedPackage, Error> {
    consume_sections(carrier, verifier, false)
}

fn consume_sections(carrier: Carrier, verifier: &impl Verifier, sections: bool) -> Result<AdmittedPackage, Error> {
    if carrier.frames.iter().any(|frame| !frame.realization.complete()) {
        return Err(Error::Structure("missing realization disclosure"));
    }
    if !verifier.publication_profile(&carrier) {
        return Err(Error::Structure("publication profile"));
    }
    let empty = pn_records::validate_history(&[], &[])?;
    let declarations = pn_records::validate_record(&[], &empty, &carrier.causes.declarations)?;
    let constants = constants::bind_constants(&declarations, carrier.causes.editions.clone())?;
    let length = u64::try_from(carrier.frames.len()).map_err(|_| Error::Structure("boundary count"))?;
    if carrier
        .causes
        .acts
        .iter()
        .any(|a| a.finalization_epoch == 0 || a.finalization_epoch > length)
    {
        return Err(Error::Structure("act outside boundary sequence"));
    }
    let mut led = initial(&carrier)?;
    let mut prior = None;
    let mut states = Vec::new();
    let mut inputs = Vec::new();
    let mut prices = Vec::new();
    let mut bindings = Vec::new();
    for (offset, frame) in carrier.frames.iter().enumerate() {
        let boundary = u64::try_from(offset).map_err(|_| Error::Structure("boundary count"))? + 1;
        if frame.parameters.boundary != boundary || frame.closure.schedule != *led.record() {
            return Err(Error::Structure("mixed boundary or led schedule"));
        }
        let RebuiltFrame {
            markers,
            input,
            price,
            history,
            binding,
        } = rebuild(&carrier, frame, offset, &declarations, &constants, verifier)?;
        bindings.push(binding);
        inputs.push(input);
        prices.push(price);
        let candidate = package::verify_candidate(
            package::CandidateInput {
                causes: package::PackageInput {
                    markers: markers.clone(),
                    history,
                    inputs: inputs.clone(),
                    prices: prices.clone(),
                    bindings: bindings.clone(),
                },
                closure: frame.closure.statement.clone(),
            },
            verifier,
            verifier,
        )?;
        let closed = closure::replay(
            &closure::ClosureInput {
                candidate: &candidate,
                partition: &frame.closure.partition,
                schedule: &led,
                previous: prior.as_ref(),
            },
            &frame.procedure,
            verifier,
            verifier,
            carrier.numeric.context()?,
            &frame.closure,
        )?;
        let state = compiler::compile_admitted(
            closed.admitted(),
            verifier,
            &mut carrier.numeric.context()?,
            frame.procedure.arithmetic.clone(),
            frame.procedure.maximum_products,
        )
        .map_err(|error| Error::Compile(Box::new(error)))?;
        if let Some(section) = disclosures::compare(state.view(), &frame.compiled) {
            if sections {
                return Err(Error::Disclosure(section));
            }
            return Err(Error::Structure("changed compiled section"));
        }
        standing(&state, frame, verifier)?;
        states.push(state);
        led = next(&carrier, &states, verifier)?;
        prior = Some(closed);
    }
    Ok(AdmittedPackage {
        carrier,
        closed: prior.ok_or(Error::Structure("empty boundary sequence"))?,
    })
}

/// Assemble only against a previously admitted close; the full consumer validation
/// prevents an omitted or mixed cause from entering an immutable package.
/// (´rule:admission:semantic-carrier´)
/// # Errors
/// Returns consumption refusals or a mismatch with the supplied admission authority.
#[tracing::instrument(
    name = "sig:design:epoch",
    fields(
        execution_owner = "EPOCH",
        claim_owner = "ROOT",
        claim_label = "sig:design:epoch",
        source_item = "publication::assemble"
    ),
    ret
)]
pub fn assemble(closed: &closure::ClosedBoundary, carrier: Carrier, verifier: &impl Verifier) -> Result<AdmittedPackage, Error> {
    if carrier.frames.last().map(|frame| &frame.closure) != Some(closed.record()) {
        return Err(Error::Structure("mixed admitted close"));
    }
    let result = consume(carrier, verifier)?;
    if result.closed.record() != closed.record() {
        return Err(Error::Structure("mixed admitted close"));
    }
    Ok(result)
}

impl AdmittedPackage {
    /// Borrow the final admitted result after complete semantic consumption.
    /// (´rule:admission:semantic-carrier´)
    /// Justified: Immutable access retains the independent admission boundary.
    #[must_use]
    pub fn boundary(&self) -> &package::AdmittedBoundary {
        self.closed.admitted()
    }

    /// Borrow the complete immutable semantic package, without implying encoded bytes.
    /// (´rule:admission:semantic-carrier´)
    /// Justified: Immutable access creates no new authority.
    #[must_use]
    pub fn carrier(&self) -> &Carrier {
        &self.carrier
    }
}
