//! Reconstructed scalar questions followed by source-adjacent endpoint transport.
//! (´[ROOT-alg:design:transport]´)
use super::super::{Error, arithmetic::singleton};
use super::records::{MapRecord, MemoStats, ScalarInput, ScalarRecord};
use crate::{base::BaseScore, solve::compact::BoundProcedure};
use nrz_cas::{Location, Rational, enclosure::Interval, limits::Budget};
use pn_graph::numeric::activation::bounded;
use pn_graph::numeric::{
    self,
    activation::{Evaluation, Quantity, Request, sharing::Session},
};
use pn_records::{
    burn::Address,
    primitive::{Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
    transport::TransportInput,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    revision: &'static str,
    plan: super::Plan,
    precision: u32,
    input: ScalarInput,
}
#[derive(Clone, Debug)]
struct Cached {
    scalar: ScalarRecord,
    exact: Option<PrimitiveRecord>,
}
#[derive(Debug, Default)]
struct Cache {
    previous: BTreeMap<Key, Cached>,
    current: BTreeMap<Key, Cached>,
    stats: MemoStats,
}
impl Cache {
    fn begin(&mut self) {
        self.previous = std::mem::take(&mut self.current);
        self.stats = MemoStats::default();
    }
}

#[derive(Debug)]
struct Checks<'a> {
    plan: super::Plan,
    cache: &'a mut Cache,
    capacity: usize,
    bounded: Vec<ScalarRecord>,
    expected_bounded: Option<&'a [ScalarRecord]>,
    policy: Procedure,
    supplied: Option<&'a [PrimitiveRecord]>,
    records: Vec<PrimitiveRecord>,
    memo: &'a mut BTreeMap<Query, PrimitiveRecord>,
    receiver: &'a mut numeric::Prepared,
    budget: Budget,
}
impl Checks<'_> {
    fn key(&mut self, input: &ScalarInput) -> Result<Key, Error> {
        let precision = self.policy.enclosure.as_ref().ok_or(Error::Scope)?.refinement.precision;
        let key = Key {
            revision: "memoized-dyadic-v4",
            plan: self.plan,
            precision,
            input: input.clone(),
        };
        self.budget.work(
            u64::try_from(format!("{key:?}").len()).map_err(|_| Error::Scope)? + 1,
            Location::new("memoized scalar key"),
        )?;
        Ok(key)
    }
    fn lookup(&mut self, key: &Key) -> Result<Option<Interval>, Error> {
        let current = self.cache.current.get(key);
        let previous = current.is_none();
        let found = current.or_else(|| self.cache.previous.get(key)).cloned();
        let Some(found) = found else {
            self.cache.stats.misses += 1;
            return Ok(None);
        };
        if self
            .expected_bounded
            .is_some_and(|rows| rows.get(self.bounded.len()) != Some(&found.scalar))
        {
            return Err(Error::Map);
        }
        let value = if let Some(exact) = &found.exact {
            if self.supplied.is_some_and(|rows| {
                rows.get(self.records.len()).is_none_or(|r| {
                    r.query != exact.query
                        || r.precision != exact.precision
                        || r.evidence.attachment != exact.evidence.attachment
                        || r.evidence.bounds != exact.evidence.bounds
                        || r.evidence.outcome != exact.evidence.outcome
                        || r.evidence.resource_fault != exact.evidence.resource_fault
                })
            }) {
                return Err(Error::Map);
            }
            self.records.push(exact.clone());
            exact.evidence.bounds.clone().ok_or(Error::Map)?
        } else {
            found.scalar.result.clone().map_err(|_| Error::Map)?
        };
        self.bounded.push(found.scalar.clone());
        self.cache.stats.hits += 1;
        self.cache.stats.previous_hits += u64::from(previous);
        self.insert(key.clone(), found)?;
        Ok(Some(value))
    }
    fn insert(&mut self, key: Key, value: Cached) -> Result<(), Error> {
        if !self.cache.current.contains_key(&key) && self.cache.current.len() >= self.capacity {
            return Err(Error::Scope);
        }
        self.cache.current.insert(key, value);
        self.cache.stats.retained = self.cache.current.len();
        Ok(())
    }
    fn save(&mut self, key: Key, exact: Option<PrimitiveRecord>) -> Result<(), Error> {
        let scalar = self.bounded.last().ok_or(Error::Map)?.clone();
        self.insert(key, Cached { scalar, exact })
    }

    fn bounded_result(
        &mut self,
        input: ScalarInput,
        start: u64,
        result: Result<Interval, bounded::Error>,
    ) -> Result<Option<Interval>, Error> {
        let result = match result {
            Ok(value) => Ok(value),
            Err(bounded::Error::Refused(reason)) => Err(reason),
            Err(bounded::Error::Arithmetic(fault)) => return Err(fault.into()),
        };
        let record = ScalarRecord {
            input,
            result,
            work: self.budget.usage().work - start,
        };
        if self
            .expected_bounded
            .is_some_and(|rows| rows.get(self.bounded.len()) != Some(&record))
        {
            return Err(Error::Map);
        }
        let value = record.result.clone().ok();
        self.bounded.push(record);
        Ok(value)
    }

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
                let input = ScalarInput::Power {
                    base: query.coordinates[0].clone(),
                    exponent: exponent.clone(),
                };
                let key = checks.key(&input)?;
                if let Some(value) = checks.lookup(&key)? {
                    endpoints.push(value);
                    continue;
                }
                let start = checks.budget.usage().work;
                let operand = Interval::singleton(endpoint, &mut checks.budget)?;
                let exponent_value = Rational::parse(exponent, &mut checks.budget)?;
                let attempted = bounded::power(&operand, &exponent_value, checks.plan.working_precision, &mut checks.budget);
                if let Some(value) = checks.bounded_result(input, start, attempted)? {
                    checks.save(key, None)?;
                    endpoints.push(value);
                } else {
                    let value = checks.retain(query)?;
                    checks.save(key, checks.records.last().cloned())?;
                    endpoints.push(value);
                }
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
    let admitted = session.setup_work();
    checks.budget.work(initial, Location::new("prepared activation constants"))?;
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
        let key = checks.key(&ScalarInput::Activation(input.clone()))?;
        if let Some(value) = checks.lookup(&key)? {
            values.push(value);
            continue;
        }
        let constants = [
            session.premises()[0].evidence.bounds.clone().ok_or(Error::Map)?,
            session.premises()[1].evidence.bounds.clone().ok_or(Error::Map)?,
        ];
        let mut refinement = checks.policy.enclosure.as_ref().ok_or(Error::Scope)?.refinement;
        let requested = refinement.precision;
        refinement.grid_ceiling = checks.plan.working_precision;
        let start = checks.budget.usage().work;
        let attempted = bounded::activation(&input, &constants, &refinement, requested, &mut checks.budget);
        if let Some(value) = checks.bounded_result(ScalarInput::Activation(input.clone()), start, attempted)? {
            checks.save(key, None)?;
            values.push(value);
            continue;
        }
        session.cap_remaining(
            checks
                .policy
                .maximum_work
                .checked_sub(checks.budget.usage().work)
                .ok_or(Error::Map)?,
        )?;
        let exact_start = session.work();
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
        checks
            .budget
            .work(session.work() - exact_start, Location::new("exact activation fallback"))?;
        values.push(record.evidence.bounds.clone().ok_or(Error::Map)?);
        checks.records.push(record.clone());
        checks.save(key, Some(record))?;
    }
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
    depth: usize,
    cached: &mut Option<StaticInput>,
    setup: &mut u64,
) -> Result<(), Error> {
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
        for name in declared.parameters().depth_mass.iter().take(depth) {
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
    Ok(())
}

struct StaticInput {
    rows: Vec<BTreeMap<usize, Interval>>,
    vectors: TransportInput<Interval>,
    records: Vec<PrimitiveRecord>,
}

pub(super) struct Context<'a, 'b> {
    plan: super::Plan,
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
    cache: Cache,
    session: Option<Session>,
    static_input: Option<StaticInput>,
    initial_work: u64,
    pub(super) setup_work: u64,
}

impl<'a, 'b> Context<'a, 'b> {
    pub(super) fn new(
        plan: super::Plan,
        bound: &'a BoundProcedure<'b>,
        rung: &str,
        precision: u32,
        remaining: u64,
    ) -> Result<Self, Error> {
        let (state, declared) = bound.inputs();
        let profile = declared.fence.as_ref().ok_or(Error::Scope)?;
        let policy = super::super::policy(declared, precision, remaining)?;
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
        let depth = state.view().support.depth;
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
            plan,
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
            cache: Cache::default(),
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
        let policy = super::super::policy(declared, precision, remaining)?;
        let mut limits = policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
        limits.work = remaining;
        self.cache.begin();
        self.memo.clear();
        if let Some(session) = &mut self.session {
            session.begin_pass()?;
        }
        let prior_setup = self.receiver.setup_work();
        let mut checks = Checks {
            plan: self.plan,
            cache: &mut self.cache,
            capacity: capacity(point.len(), self.exponents.len())?,
            bounded: Vec::new(),
            expected_bounded: supplied.map(|r| r.bounded.as_slice()),
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
        let exponents = &self.exponents;
        for value in point.values() {
            if Rational::parse(value, &mut checks.budget)?.is_negative() {
                return Err(Error::Scope);
            }
        }
        let values = if self.zero {
            vec![singleton("1", &mut checks.budget)?; point.len()]
        } else {
            activations(
                &mut checks,
                point,
                &self.wall,
                &self.bleed,
                bound.enclosed_wall(),
                &mut self.session,
                &mut self.setup_work,
            )?
        };
        inputs(
            bound,
            &mut checks,
            exponents.len(),
            &mut self.static_input,
            &mut self.setup_work,
        )?;
        let retained = self.static_input.as_ref().ok_or(Error::Map)?;
        let (mut output, mut composition) = compose(&mut checks, retained, &values, exponents, self.zero, remaining)?;
        intersect_hull(
            &mut output.standing,
            state.view().support.ranges.values().map(|r| (&r.minimum, &r.maximum)),
            &mut composition,
        )?;
        let image = super::super::image(&output.standing, &self.actors, &mut composition)?;
        if supplied.is_some_and(|r| {
            r.memo != checks.cache.stats
                || r.bounded.len() != checks.bounded.len()
                || r.image != image
                || r.primitives.len() != checks.records.len()
                || r.transport != output
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
            bounded: checks.bounded,
            memo: checks.cache.stats.clone(),
            image,
            transport: output,
            work: composition.usage().work,
            composition_work: composition.usage().work - checks.budget.usage().work,
        })
    }
}

fn compose(
    checks: &mut Checks<'_>,
    retained: &StaticInput,
    values: &[Interval],
    exponents: &[String],
    zero: bool,
    remaining: u64,
) -> Result<(pn_graph::transport::applied::Output, Budget), Error> {
    let before = checks.budget.usage().work;
    let precision = checks.policy.enclosure.as_ref().ok_or(Error::Scope)?.refinement.precision;
    let maximum_cells =
        usize::try_from(checks.policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.proof_nodes).map_err(|_| Error::Scope)?;
    let mut limits = checks.policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
    limits.work = remaining;
    let mut composition = Budget::new(limits)?;
    composition.work(before, Location::new("prepared scalar prefix"))?;
    let mut factors = Factors {
        checks,
        values,
        exponents,
        zero,
        remaining,
        error: None,
    };
    let output = pn_graph::transport::applied::evaluate(
        &pn_graph::transport::applied::Input {
            rows: &retained.rows,
            depth_mass: &retained.vectors.depth_mass,
            emission: &retained.vectors.emission,
            counts: &retained.vectors.counts,
            rates: &retained.vectors.rates,
        },
        precision,
        maximum_cells,
        &mut composition,
        &mut factors,
    );
    if let Some(error) = factors.error.take() {
        return Err(error);
    }
    let output = output?;
    Ok((output, composition))
}

#[derive(Debug)]
struct Factors<'a, 'b> {
    checks: &'a mut Checks<'b>,
    values: &'a [Interval],
    exponents: &'a [String],
    zero: bool,
    remaining: u64,
    error: Option<Error>,
}
impl pn_graph::transport::applied::HopFactors for Factors<'_, '_> {
    #[tracing::instrument(
        name = "sig:design:epoch",
        fields(
            execution_owner = "EPOCH",
            claim_owner = "ROOT",
            claim_label = "sig:design:epoch",
            source_item = "conserved::memoized::map::<Factors < '_ , '_ > as pn_graph :: transport :: applied :: HopFactors>::at"
        ),
        ret
    )]
    fn at(&mut self, depth: usize, b: &mut Budget) -> Result<Vec<Interval>, pn_graph::transport::applied::Error> {
        self.checks.memo.clear();
        let start = self.checks.budget.usage().work;
        let outside = b
            .usage()
            .work
            .checked_sub(start)
            .ok_or(pn_graph::transport::applied::Error::Scope)?;
        self.checks.policy.maximum_work = self
            .remaining
            .checked_sub(outside)
            .ok_or(pn_graph::transport::applied::Error::Scope)?;
        let result = if self.zero {
            Ok(self.values.to_vec())
        } else {
            powers(self.checks, self.values, &self.exponents[depth..=depth]).map(|mut v| v.remove(0))
        };
        match result {
            Ok(values) => {
                b.work(self.checks.budget.usage().work - start, Location::new("prepared hop powers"))?;
                Ok(values)
            }
            Err(e) => {
                self.error = Some(e);
                Err(pn_graph::transport::applied::Error::Scope)
            }
        }
    }
}

/// Claim: Complete typed scalar keys distinguish changed input, plan, precision and revision; rotation retains precisely the previous pass and drops older requests.
/// ´claim:numerics:memoized-keys-retain-complete-scope´
/// ´test:unit:memoized-key-scope´
#[test]
fn memoized_key_scope() {
    let key = Key {
        revision: "memoized-dyadic-v4",
        plan: super::Plan { working_precision: 32 },
        precision: 16,
        input: ScalarInput::Power {
            base: Range {
                lower: "1".into(),
                upper: "1".into(),
            },
            exponent: "1/2".into(),
        },
    };
    let value = Cached {
        scalar: ScalarRecord {
            input: key.input.clone(),
            result: Err(bounded::Refusal::TargetNotCertifiable),
            work: 17,
        },
        exact: None,
    };
    let mut cache = Cache::default();
    cache.current.insert(key.clone(), value.clone());
    cache.begin();
    assert_eq!(cache.previous.get(&key).unwrap().scalar, value.scalar);
    let mut changes = vec![key.clone(); 4];
    changes[0].revision = "bounded-activation-v3";
    changes[1].plan.working_precision = 33;
    changes[2].precision = 17;
    changes[3].input = ScalarInput::Power {
        base: Range {
            lower: "1".into(),
            upper: "2".into(),
        },
        exponent: "1/2".into(),
    };
    for changed in changes {
        assert!(!cache.previous.contains_key(&changed));
    }
    cache.begin();
    assert!(cache.previous.is_empty());
}

fn intersect_hull<'a>(
    values: &mut [Interval],
    ranges: impl Iterator<Item = (&'a String, &'a String)>,
    budget: &mut Budget,
) -> Result<(), Error> {
    // The independent exact contributing hull never selects a threshold verdict.
    for (value, (minimum, maximum)) in values.iter_mut().zip(ranges) {
        let hull = Interval::new(Rational::parse(minimum, budget)?, Rational::parse(maximum, budget)?, budget)?;
        *value = value.intersection(&hull, budget)?;
    }
    Ok(())
}

fn capacity(actors: usize, depth: usize) -> Result<usize, Error> {
    actors
        .checked_mul(depth.checked_mul(2).and_then(|v| v.checked_add(1)).ok_or(Error::Scope)?)
        .ok_or(Error::Scope)
}
