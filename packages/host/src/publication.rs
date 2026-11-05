//! Canonical test-publication bytes carry disclosures, never admission authority.
//! (´[ROOT-amend:design:nested-publication-fields]´)
mod backend_budget;
mod backend_enclosure_derivative;
mod backend_enclosure_exp;
mod backend_enclosure_log;
mod backend_enclosure_mod;
mod backend_enclosure_model;
mod backend_enclosure_power;
mod backend_error;
mod epoch_admission;
mod epoch_admission_finalize;
mod epoch_base;
mod epoch_cells;
mod epoch_compiler;
mod epoch_controller;
mod epoch_fence;
mod epoch_ledger;
mod epoch_lib;
mod epoch_package;
mod epoch_publication;
mod epoch_publication_disclosures;
mod epoch_recipients;
mod epoch_schedules;
mod epoch_support;
mod graph_recognition;
mod graph_title;
mod records_authentication;
mod records_burn;
mod records_commitments;
mod records_conserved;
mod records_constants;
mod records_controller;
mod records_lib;
mod records_numerics;
mod records_numerics_price_input;
mod records_primitive;
mod records_ridge;
mod records_solve;
mod records_transport;
mod records_wall;
mod scalars;
mod wire;

use pn_epoch::publication::{self as p, disclosures as d};
use pn_interchange::{Content, ContentKey, Document, Envelope, NamespaceLabel, Value, Version};
use pn_records::numerics::NumericContext;
use wire::{Context, Wire, array, array_fields, finish, take};

/// Structural refusal of a publication disclosure; none denotes failed admission.
/// (´[ROOT-amend:design:nested-publication-fields]´)
#[derive(Debug)]
pub enum Error {
    /// Invalid canonical CBOR or envelope.
    Encoding,
    /// Unknown namespace or version.
    Edition,
    /// A patch version outside this theory's exact byte identity.
    Patch,
    /// Missing, extra or wrongly typed field or unknown variant.
    Shape,
    /// A declared integer range was exceeded.
    Range,
    /// A numeric spelling or reduced pair is not canonical.
    CanonicalNumber,
    /// A set or map repeats a semantic value or is not structurally ordered.
    Order,
    /// The caller's explicit exact-arithmetic context refused reconstruction.
    Arithmetic(d::Fault),
    /// A public dimensioned value cannot be reconstructed.
    Numeric(pn_records::numerics::NumericError),
}

fn sections(disclosure: &d::Disclosure, c: &mut Context<'_>) -> Result<[Value; 7], Error> {
    let d::Disclosure { causes, numeric, frames } = disclosure;
    let p::Causes {
        acts,
        names,
        declarations,
        editions,
    } = causes;
    let mut sequences = Vec::new();
    let mut ledgers = Vec::new();
    let mut projections = Vec::new();
    let mut transports = Vec::new();
    let mut standings = Vec::new();
    let mut closures = Vec::new();
    let mut reproductions = Vec::new();
    for frame in frames {
        let d::Boundary {
            realization,
            burn,
            marker_policy,
            marker_history,
            parameters,
            price,
            sequence,
            procedure,
            compiled,
            closure,
            standing,
            next,
        } = frame;
        let d::Compiled {
            title,
            ledger,
            cells,
            coefficients,
            recipients,
            base,
            support,
        } = compiled;
        let d::Closure {
            markers,
            bindings,
            statement,
            partition,
            final_gates,
            schedule,
        } = closure;
        sequences.push(array([sequence.write(c)?, statement.write(c)?, partition.write(c)?]));
        ledgers.push(ledger.write(c)?);
        projections.push(array([
            cells.write(c)?,
            coefficients.write(c)?,
            recipients.write(c)?,
            base.write(c)?,
        ]));
        transports.push(support.write(c)?);
        standings.push(array([standing.write(c)?, final_gates.write(c)?]));
        closures.push(array([title.write(c)?, schedule.write(c)?, next.write(c)?]));
        reproductions.push(array([
            realization.write(c)?,
            burn.write(c)?,
            parameters.write(c)?,
            price.write(c)?,
            procedure.write(c)?,
            marker_policy.write(c)?,
            marker_history.write(c)?,
            markers.write(c)?,
            bindings.write(c)?,
        ]));
    }
    Ok([
        array([wire::write_set(acts, c)?, names.write(c)?, array(sequences)]),
        array(ledgers),
        array(projections),
        array(transports),
        array(standings),
        array(closures),
        array([
            wire::write_set(declarations, c)?,
            wire::write_set(editions, c)?,
            numeric.write(c)?,
            array(reproductions),
        ]),
    ])
}

fn read_sections(values: [&Value; 7], c: &mut Context<'_>) -> Result<d::Disclosure, Error> {
    let mut accepted = array_fields(values[0])?;
    let acts = wire::read_set(accepted.next().ok_or(Error::Shape)?, c)?;
    let names = take(&mut accepted, c)?;
    let mut sequences = array_fields(accepted.next().ok_or(Error::Shape)?)?;
    finish(accepted)?;
    let mut ledgers = array_fields(values[1])?;
    let mut projections = array_fields(values[2])?;
    let mut transports = array_fields(values[3])?;
    let mut standings = array_fields(values[4])?;
    let mut closures = array_fields(values[5])?;
    let mut reproduction = array_fields(values[6])?;
    let declarations = wire::read_set(reproduction.next().ok_or(Error::Shape)?, c)?;
    let editions = wire::read_set(reproduction.next().ok_or(Error::Shape)?, c)?;
    let numeric = take(&mut reproduction, c)?;
    let reproduction_frames = array_fields(reproduction.next().ok_or(Error::Shape)?)?;
    finish(reproduction)?;
    let mut frames = Vec::new();
    for value in reproduction_frames {
        let mut r = array_fields(value)?;
        let realization = take(&mut r, c)?;
        let burn = take(&mut r, c)?;
        let parameters = take(&mut r, c)?;
        let price = take(&mut r, c)?;
        let procedure = take(&mut r, c)?;
        let marker_policy = take(&mut r, c)?;
        let marker_history = take(&mut r, c)?;
        let markers = take(&mut r, c)?;
        let bindings = take(&mut r, c)?;
        finish(r)?;
        let mut projection = array_fields(projections.next().ok_or(Error::Shape)?)?;
        let cells = take(&mut projection, c)?;
        let coefficients = take(&mut projection, c)?;
        let recipients = take(&mut projection, c)?;
        let base = take(&mut projection, c)?;
        finish(projection)?;
        let mut closure_fields = array_fields(closures.next().ok_or(Error::Shape)?)?;
        let title = take(&mut closure_fields, c)?;
        let schedule = take(&mut closure_fields, c)?;
        let next = take(&mut closure_fields, c)?;
        finish(closure_fields)?;
        let mut accepted_frame = array_fields(sequences.next().ok_or(Error::Shape)?)?;
        let sequence = take(&mut accepted_frame, c)?;
        let statement = take(&mut accepted_frame, c)?;
        let partition = take(&mut accepted_frame, c)?;
        finish(accepted_frame)?;
        let ledger = take(&mut ledgers, c)?;
        let support = take(&mut transports, c)?;
        let mut standing_frame = array_fields(standings.next().ok_or(Error::Shape)?)?;
        let standing = take(&mut standing_frame, c)?;
        let final_gates = take(&mut standing_frame, c)?;
        finish(standing_frame)?;
        let closure = d::Closure {
            markers,
            bindings,
            statement,
            partition,
            final_gates,
            schedule,
        };
        frames.push(d::Boundary {
            realization,
            burn,
            marker_policy,
            marker_history,
            parameters,
            price,
            sequence,
            procedure,
            compiled: d::Compiled {
                title,
                ledger,
                cells,
                coefficients,
                recipients,
                base,
                support,
            },
            closure,
            standing,
            next,
        });
    }
    finish(sequences)?;
    finish(ledgers)?;
    finish(projections)?;
    finish(transports)?;
    finish(standings)?;
    finish(closures)?;
    Ok(d::Disclosure {
        causes: p::Causes {
            acts,
            names,
            declarations,
            editions,
        },
        numeric,
        frames,
    })
}

/// Encode all disclosure fields under the immutable test theory. No admission is performed.
/// (´[ROOT-amend:design:nested-publication-fields]´)
/// # Errors
/// Refuses an exact scalar operation outside the caller's declared limits.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::encode"
    ),
    ret
)]
pub fn encode(disclosure: &d::Disclosure, numeric: &mut NumericContext, limits: d::Limits) -> Result<Vec<u8>, Error> {
    let mut context = Context {
        numeric,
        arithmetic: d::limits::Budget::new(limits).map_err(Error::Arithmetic)?,
    };
    let mut payload = Content::new();
    for (key, value) in (2..=8).zip(sections(disclosure, &mut context)?) {
        payload.insert(ContentKey::new(key).map_err(|_| Error::Shape)?, value);
    }
    let label = NamespaceLabel::parse("org.peer-network.test.publication").map_err(|_| Error::Edition)?;
    Ok(Document::new(Envelope::new(label, Version::new(1, 0, 0)), payload).to_canonical_bytes())
}

/// Decode canonical bytes to untrusted disclosures. Only epoch's restore function grants authority.
/// (´[ROOT-amend:design:nested-publication-fields]´)
/// # Errors
/// Refuses malformed, noncanonical or unsupported documents and bounded scalar reconstruction.
#[tracing::instrument(
    name = "rule:publication:codec",
    fields(
        execution_owner = "HOST",
        claim_owner = "HOST",
        claim_label = "rule:publication:codec",
        source_item = "publication::decode"
    ),
    ret
)]
pub fn decode(bytes: &[u8], numeric: &mut NumericContext, limits: d::Limits) -> Result<d::Disclosure, Error> {
    let document = Document::from_canonical_bytes(bytes).map_err(|_| Error::Encoding)?;
    if document.envelope().label() != &NamespaceLabel::parse("org.peer-network.test.publication").map_err(|_| Error::Edition)?
        || document.envelope().version().major() != 1
        || document.envelope().version().minor() != 0
    {
        return Err(Error::Edition);
    }
    if document.envelope().version().patch() != 0 {
        return Err(Error::Patch);
    }
    if !matches!(
        pn_interchange::accept(registry()?, &document),
        pn_interchange::Verdict::AcceptedStrictly { minor: 0 }
    ) {
        return Err(Error::Shape);
    }
    if document.content().len() != 7 {
        return Err(Error::Shape);
    }
    let values = (2..=8)
        .map(|key| document.content().get(key).ok_or(Error::Shape))
        .collect::<Result<Vec<_>, _>>()?;
    let values = values.try_into().map_err(|_| Error::Shape)?;
    let mut context = Context {
        numeric,
        arithmetic: d::limits::Budget::new(limits).map_err(Error::Arithmetic)?,
    };
    read_sections(values, &mut context)
}

fn registry() -> Result<&'static pn_interchange::Registry, Error> {
    static REGISTRY: std::sync::OnceLock<Option<pn_interchange::Registry>> = std::sync::OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let label = NamespaceLabel::parse("org.peer-network.test.publication").ok()?;
            let theory = pn_interchange::Theory::parse(include_str!("publication/publication.cddl")).ok()?;
            let mut registry = pn_interchange::Registry::new();
            registry.acquire(pn_interchange::Coordinate::new(label, 1, 0), theory).ok()?;
            Some(registry)
        })
        .as_ref()
        .ok_or(Error::Shape)
}
