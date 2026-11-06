//! Reconstructed scalar questions followed by source-adjacent endpoint transport.
//! (´[ROOT-alg:design:transport]´)
use super::{
    Error,
    arithmetic::{multiply, singleton},
};
use crate::{base::BaseScore, solve::BoundProcedure};
use nrz_cas::{Location, Rational, enclosure::Interval, limits::Budget};
use pn_graph::numeric::{
    self,
    activation::{Evaluation, Quantity, Request, sharing::Session},
};
use pn_records::{
    burn::Address,
    conserved::MapRecord,
    primitive::{Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
    transport::TransportInput,
};
use std::collections::BTreeMap;

struct Checks<'a> {
    policy: Procedure,
    supplied: Option<&'a [PrimitiveRecord]>,
    records: Vec<PrimitiveRecord>,
    memo: &'a mut BTreeMap<Query, PrimitiveRecord>,
    receiver: &'a mut numeric::Prepared,
    budget: Budget,
}
impl Checks<'_> {
    fn retain(&mut self, expected: Query) -> Result<Interval, Error> {
        self.budget.work(1, Location::new("conserved request lookup"))?;
        let supplied = self
            .supplied
            .map(|v| v.get(self.records.len()).ok_or(Error::Map))
            .transpose()?;
        let precision = self.policy.enclosure.as_ref().ok_or(Error::Scope)?.refinement.precision;
        if supplied.is_some_and(|r| r.query != expected || r.precision != precision) {
            return Err(Error::Map);
        }
        let key_work = u64::try_from(format!("{expected:?}").len()).map_err(|_| Error::Scope)?;
        self.budget.work(key_work, Location::new("prepared request key"))?;
        let cached = self.memo.get(&expected).cloned();
        let record = if let Some(record) = cached {
            if supplied.is_some_and(|r| {
                r.evidence.attachment != record.evidence.attachment
                    || r.evidence.bounds != record.evidence.bounds
                    || r.evidence.outcome != record.evidence.outcome
                    || r.evidence.resource_fault != record.evidence.resource_fault
            }) {
                return Err(Error::Map);
            }
            record
        } else {
            let mut policy = self.policy.clone();
            let remaining = policy.maximum_work.checked_sub(self.budget.usage().work).ok_or(Error::Map)?;
            let limits = &mut policy.enclosure.as_mut().ok_or(Error::Scope)?.operation;
            limits.work = limits.work.min(remaining);
            let attachment = supplied
                .map(|r| r.evidence.attachment.as_ref().ok_or(Error::Map))
                .transpose()?;
            let evidence = self.receiver.run(&expected, attachment, limits.work)?;
            if let Some(fault) = &evidence.resource_fault {
                return Err(numeric::Error::Resource(fault.clone()).into());
            }
            if supplied.is_some_and(|r| {
                r.evidence.bounds != evidence.bounds
                    || r.evidence.outcome != evidence.outcome
                    || r.evidence.resource_fault != evidence.resource_fault
            }) {
                return Err(Error::Map);
            }
            if u64::try_from(self.memo.len()).map_err(|_| Error::Scope)?
                >= self.policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.proof_nodes
            {
                return Err(Error::Map);
            }
            self.budget.work(evidence.work, Location::new("conserved scalar request"))?;
            let record = PrimitiveRecord {
                query: expected.clone(),
                precision,
                evidence,
            };
            self.memo.insert(expected, record.clone());
            record
        };
        if record.evidence.resource_fault.is_some() || record.evidence.attachment.is_none() {
            return Err(Error::Map);
        }
        let value = record.evidence.bounds.clone().ok_or(Error::Map)?;
        self.records.push(record);
        Ok(value)
    }
}

fn powers(checks: &mut Checks<'_>, values: &[Interval], exponents: &[String]) -> Result<Vec<Vec<Interval>>, Error> {
    let mut result = Vec::new();
    for exponent in exponents {
        let mut row = Vec::new();
        for value in values {
            if value.lower().is_zero() || value.lower().is_negative() {
                return Err(Error::Map);
            }
            let mut endpoints = Vec::new();
            for endpoint in [value.lower(), value.upper()] {
                let query = Query {
                    coordinates: vec![Range {
                        lower: endpoint.exact_string(&mut checks.budget)?,
                        upper: endpoint.exact_string(&mut checks.budget)?,
                    }],
                    nodes: vec![Node::Coordinate(0), Node::PositivePower(0, exponent.clone())],
                    target: 1,
                    goal: Goal::Width,
                };
                endpoints.push(checks.retain(query)?);
            }
            row.push(Interval::new(
                endpoints[0].lower().clone(),
                endpoints[1].upper().clone(),
                &mut checks.budget,
            )?);
        }
        result.push(row);
    }
    Ok(result)
}

fn activations(
    checks: &mut Checks<'_>,
    points: &BTreeMap<String, String>,
    wall: &str,
    bleed: &str,
    enclosed_wall: Option<&Range>,
    retained: &mut Option<Session>,
    setup: &mut u64,
) -> Result<Vec<Interval>, Error> {
    let mut initial = 0;
    if retained.is_none() {
        let records = checks.supplied.map(|r| r.get(..2).ok_or(Error::Map)).transpose()?;
        let mut policy = checks.policy.clone();
        policy.maximum_work = policy
            .maximum_work
            .checked_sub(checks.budget.usage().work)
            .ok_or(Error::Map)?;
        let limits = &mut policy.enclosure.as_mut().ok_or(Error::Scope)?.operation;
        limits.work = limits.work.min(policy.maximum_work);
        let session = Session::prepared(&policy, bleed, records)?;
        initial = session.work();
        *setup += initial;
        *retained = Some(session);
    }
    let session = retained.as_mut().ok_or(Error::Map)?;
    let start = session.work();
    let admitted = session.setup_work();
    session.cap_remaining(
        checks
            .policy
            .maximum_work
            .checked_sub(checks.budget.usage().work)
            .and_then(|n| n.checked_sub(initial))
            .ok_or(Error::Map)?,
    )?;
    if checks.supplied.is_some_and(|r| {
        r.get(..2).is_none_or(|v| {
            v.iter().zip(session.premises()).any(|(a, b)| {
                a.query != b.query
                    || a.precision != b.precision
                    || a.evidence.attachment != b.evidence.attachment
                    || a.evidence.bounds != b.evidence.bounds
                    || a.evidence.outcome != b.evidence.outcome
                    || a.evidence.resource_fault != b.evidence.resource_fault
            })
        })
    }) {
        return Err(Error::Map);
    }
    checks.records.extend_from_slice(session.premises());
    let mut values = Vec::new();
    for value in points.values() {
        let input = Request {
            standing: Range {
                lower: value.clone(),
                upper: value.clone(),
            },
            bleed_squared: bleed.into(),
            wall: enclosed_wall.is_none().then(|| wall.into()),
            wall_enclosure: enclosed_wall.cloned(),
            quantity: Quantity::Clamped,
        };
        let record = if let Some(records) = checks.supplied {
            let supplied = records.get(checks.records.len()).ok_or(Error::Map)?;
            session.replay(&Evaluation {
                input,
                primitive: supplied.clone(),
            })?
        } else {
            let index = session.evaluate(&input)?;
            session.evidence(index).ok_or(Error::Map)?.primitive.clone()
        };
        values.push(record.evidence.bounds.clone().ok_or(Error::Map)?);
        checks.records.push(record);
    }
    checks
        .budget
        .work(initial + session.work() - start, Location::new("prepared activation session"))?;
    *setup += session.setup_work() - admitted;
    Ok(values)
}

fn base(checks: &mut Checks<'_>, value: &BaseScore) -> Result<Interval, Error> {
    let BaseScore::Held { exact_part, terms } = value else {
        let BaseScore::Exact(value) = value else {
            return Err(Error::Map);
        };
        return singleton(value, &mut checks.budget);
    };
    let mut nodes = vec![Node::Rational(exact_part.clone())];
    let mut sum = 0;
    for term in terms {
        let n = nodes.len();
        nodes.extend([
            Node::Rational(term.radicand.clone()),
            Node::SquareRoot(n),
            Node::Rational(term.domain_factor.clone()),
            Node::Multiply(n + 1, n + 2),
            Node::Add(sum, n + 3),
        ]);
        sum = n + 4;
    }
    checks.retain(Query {
        coordinates: Vec::new(),
        nodes,
        target: sum,
        goal: Goal::Width,
    })
}

fn inputs(
    bound: &BoundProcedure<'_>,
    checks: &mut Checks<'_>,
    powers: &[Vec<Interval>],
    cached: &mut Option<StaticInput>,
    setup: &mut u64,
) -> Result<TransportInput<Interval>, Error> {
    if cached.is_none() {
        let start = checks.budget.usage().work;
        let records_start = checks.records.len();
        let admitted_start = checks.receiver.setup_work();
        let state = bound.inputs().0;
        let view = state.view();
        let declared = state.package().input().inputs.last().ok_or(Error::Scope)?;
        let actors: Vec<_> = view.base.rows.keys().cloned().collect();
        let indices: BTreeMap<_, _> = actors.iter().enumerate().map(|(i, a)| (a, i)).collect();
        let mut rows = Vec::new();
        for row in view.base.rows.values() {
            let mut next = BTreeMap::new();
            for (target, entry) in row {
                next.insert(*indices.get(target).ok_or(Error::Scope)?, base(checks, &entry.score)?);
            }
            rows.push(next);
        }
        let mut result = TransportInput {
            hops: Vec::new(),
            depth_mass: Vec::new(),
            emission: Vec::new(),
            counts: Vec::new(),
            rates: Vec::new(),
        };
        for name in declared.parameters().depth_mass.iter().take(powers.len()) {
            result.depth_mass.push(Interval::singleton(
                &crate::constant(declared.constants(), name, &mut checks.budget)?,
                &mut checks.budget,
            )?);
        }
        for actor in &actors {
            let source = view.support.sources.get(actor).ok_or(Error::Scope)?;
            result.emission.push(singleton(&source.emission, &mut checks.budget)?);
            result.rates.push(singleton(&source.reduced_rate, &mut checks.budget)?);
            result.counts.push(singleton(
                &view
                    .ledger
                    .counts
                    .get(&Address(actor.clone()))
                    .ok_or(Error::Scope)?
                    .0
                    .to_string(),
                &mut checks.budget,
            )?);
        }
        *setup += checks.budget.usage().work - start - (checks.receiver.setup_work() - admitted_start);
        *cached = Some(StaticInput {
            rows,
            vectors: result,
            records: checks.records[records_start..].to_vec(),
        });
    } else {
        let retained = cached.as_ref().ok_or(Error::Map)?;
        for record in &retained.records {
            if checks.supplied.is_some_and(|r| {
                r.get(checks.records.len()).is_none_or(|v| {
                    v.query != record.query
                        || v.precision != record.precision
                        || v.evidence.attachment != record.evidence.attachment
                        || v.evidence.bounds != record.evidence.bounds
                        || v.evidence.outcome != record.evidence.outcome
                        || v.evidence.resource_fault != record.evidence.resource_fault
                })
            }) {
                return Err(Error::Map);
            }
            checks.records.push(record.clone());
        }
    }
    let retained = cached.as_ref().ok_or(Error::Map)?;
    let rows = &retained.rows;
    let mut result = retained.vectors.clone();
    let mut hops = Vec::new();
    for power in powers {
        let mut hop = rows.clone();
        for (source, row) in hop.iter_mut().enumerate() {
            for (target, entry) in row {
                if source != *target {
                    *entry = multiply(entry, &power[*target], &mut checks.budget)?;
                }
            }
        }
        hops.push(hop);
    }
    result.hops = hops;
    Ok(result)
}

struct StaticInput {
    rows: Vec<BTreeMap<usize, Interval>>,
    vectors: TransportInput<Interval>,
    records: Vec<PrimitiveRecord>,
}

pub(super) struct Context<'a, 'b> {
    bound: &'a BoundProcedure<'b>,
    rung: String,
    precision: u32,
    actors: Vec<String>,
    wall: String,
    bleed: String,
    zero: bool,
    exponents: Vec<String>,
    receiver: numeric::Prepared,
    memo: BTreeMap<Query, PrimitiveRecord>,
    session: Option<Session>,
    static_input: Option<StaticInput>,
    initial_work: u64,
    pub(super) setup_work: u64,
}

impl<'a, 'b> Context<'a, 'b> {
    pub(super) fn new(bound: &'a BoundProcedure<'b>, rung: &str, precision: u32, remaining: u64) -> Result<Self, Error> {
        let (state, declared) = bound.inputs();
        let profile = declared.fence.as_ref().ok_or(Error::Scope)?;
        let policy = super::policy(declared, precision, remaining)?;
        let mut limits = policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
        limits.work = remaining;
        let mut budget = Budget::new(limits)?;
        let frozen = state.package().input().inputs.last().ok_or(Error::Scope)?;
        let wall = state.package().input().prices.last().ok_or(Error::Scope)?.wall().exact();
        let bleed = crate::constant(frozen.constants(), &profile.bleed_squared, &mut budget)?.exact_string(&mut budget)?;
        let strength = Rational::parse(rung, &mut budget)?;
        if profile.inverse_wall && bound.enclosed_wall().is_none() && !strength.is_zero() && !state.view().base.rows.is_empty() {
            return Err(crate::fence::Error::ReferenceWall.into());
        }
        let depth = state.view().support.by_depth.keys().next_back().copied().unwrap_or(0);
        let exponents = profile
            .shape
            .iter()
            .take(depth)
            .map(|name| {
                Ok(strength
                    .mul(&crate::constant(frozen.constants(), name, &mut budget)?, &mut budget)?
                    .exact_string(&mut budget)?)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let initial_work = budget.usage().work;
        Ok(Self {
            bound,
            rung: rung.into(),
            precision,
            actors: state.view().base.rows.keys().cloned().collect(),
            wall: wall.into(),
            bleed,
            zero: strength.is_zero(),
            exponents,
            receiver: numeric::Prepared::new(&policy),
            memo: BTreeMap::new(),
            session: None,
            static_input: None,
            initial_work,
            setup_work: initial_work,
        })
    }
    pub(super) fn run(
        &mut self,
        point: &BTreeMap<String, String>,
        remaining: u64,
        supplied: Option<&MapRecord>,
    ) -> Result<MapRecord, Error> {
        let bound = self.bound;
        let rung = self.rung.as_str();
        let precision = self.precision;
        let (state, declared) = bound.inputs();
        if !declared.grid.iter().any(|r| r == rung)
            || point.keys().ne(state.view().base.rows.keys())
            || supplied.is_some_and(|r| {
                r.edition != declared.edition
                    || r.boundary != declared.boundary
                    || r.wall_enclosure.as_ref() != bound.enclosed_wall()
            })
        {
            return Err(Error::Scope);
        }
        let policy = super::policy(declared, precision, remaining)?;
        let mut limits = policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
        limits.work = remaining;
        let prior_setup = self.receiver.setup_work();
        let mut checks = Checks {
            policy,
            supplied: supplied.map(|r| r.primitives.as_slice()),
            records: Vec::new(),
            memo: &mut self.memo,
            receiver: &mut self.receiver,
            budget: Budget::new(limits)?,
        };
        checks
            .budget
            .work(self.initial_work, Location::new("prepared immutable setup"))?;
        self.initial_work = 0;
        let wall = self.wall.as_str();
        let bleed = self.bleed.as_str();
        let exponents = &self.exponents;
        for value in point.values() {
            if Rational::parse(value, &mut checks.budget)?.is_negative() {
                return Err(Error::Scope);
            }
        }
        let powers = if self.zero {
            vec![vec![singleton("1", &mut checks.budget)?; point.len()]; exponents.len()]
        } else {
            let values = activations(
                &mut checks,
                point,
                wall,
                bleed,
                bound.enclosed_wall(),
                &mut self.session,
                &mut self.setup_work,
            )?;
            powers(&mut checks, &values, exponents)?
        };
        let input = inputs(bound, &mut checks, &powers, &mut self.static_input, &mut self.setup_work)?;
        let before = checks.budget.usage().work;
        let maximum_cells = usize::try_from(checks.policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.proof_nodes)
            .map_err(|_| Error::Scope)?;
        let output = pn_graph::transport::enclosed::evaluate(&input, &mut checks.budget, maximum_cells)?;
        let image = super::image(&output.standing, &self.actors, &mut checks.budget)?;
        if supplied.is_some_and(|r| {
            r.image != image || r.primitives.len() != checks.records.len() || r.transport_input != input || r.transport != output
        }) {
            return Err(Error::Map);
        }
        self.setup_work += checks.receiver.setup_work() - prior_setup;
        Ok(MapRecord {
            edition: declared.edition.clone(),
            boundary: declared.boundary,
            point: point.clone(),
            rung: rung.into(),
            precision,
            wall_enclosure: bound.enclosed_wall().cloned(),
            primitives: checks.records,
            image,
            transport_input: input,
            transport: output,
            work: checks.budget.usage().work,
            composition_work: checks.budget.usage().work - before,
        })
    }
}
