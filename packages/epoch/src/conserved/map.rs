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
    memo: Vec<(Query, PrimitiveRecord)>,
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
        let mut cached = None;
        for (key, value) in &self.memo {
            self.budget.work(1, Location::new("conserved request comparison"))?;
            if key == &expected {
                cached = Some(value.clone());
                break;
            }
        }
        let record = if let Some(record) = cached {
            if supplied.is_some_and(|r| r.evidence.attachment != record.evidence.attachment) {
                return Err(Error::Map);
            }
            record
        } else {
            let mut policy = self.policy.clone();
            let remaining = policy.maximum_work.checked_sub(self.budget.usage().work).ok_or(Error::Map)?;
            let limits = &mut policy.enclosure.as_mut().ok_or(Error::Scope)?.operation;
            limits.work = limits.work.min(remaining);
            let evidence = if let Some(record) = supplied {
                numeric::replay(
                    &policy,
                    &expected,
                    record.evidence.attachment.as_ref().ok_or(Error::Map)?,
                    None,
                )?
            } else {
                numeric::evaluate(&policy, &expected, None)?
            };
            if let Some(fault) = &evidence.resource_fault {
                return Err(numeric::Error::Resource(fault.clone()).into());
            }
            self.budget.work(evidence.work, Location::new("conserved scalar request"))?;
            let record = PrimitiveRecord {
                query: expected.clone(),
                precision,
                evidence,
            };
            self.memo.push((expected, record.clone()));
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
                    coordinates: Vec::new(),
                    nodes: vec![
                        Node::Rational(endpoint.exact_string(&mut checks.budget)?),
                        Node::PositivePower(0, exponent.clone()),
                    ],
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
) -> Result<Vec<Interval>, Error> {
    let mut session = if let Some(records) = checks.supplied {
        Session::from_evidence(&checks.policy, bleed, records.get(..2).ok_or(Error::Map)?)?
    } else {
        Session::new(&checks.policy, bleed)?
    };
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
        .work(session.work(), Location::new("conserved activation session"))?;
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
) -> Result<TransportInput<Interval>, Error> {
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
    let mut result = TransportInput {
        hops,
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
    Ok(result)
}

pub(super) fn run(
    bound: &BoundProcedure<'_>,
    rung: &str,
    point: &BTreeMap<String, String>,
    precision: u32,
    remaining: u64,
    supplied: Option<&MapRecord>,
) -> Result<MapRecord, Error> {
    let (state, declared) = bound.inputs();
    let profile = declared.fence.as_ref().ok_or(Error::Scope)?;
    if !declared.grid.iter().any(|r| r == rung)
        || point.keys().ne(state.view().base.rows.keys())
        || supplied.is_some_and(|r| {
            r.edition != declared.edition || r.boundary != declared.boundary || r.wall_enclosure.as_ref() != bound.enclosed_wall()
        })
    {
        return Err(Error::Scope);
    }
    let policy = super::policy(declared, precision, remaining)?;
    let mut limits = policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.clone();
    limits.work = remaining;
    let mut checks = Checks {
        policy,
        supplied: supplied.map(|r| r.primitives.as_slice()),
        records: Vec::new(),
        memo: Vec::new(),
        budget: Budget::new(limits)?,
    };
    let frozen = state.package().input().inputs.last().ok_or(Error::Scope)?;
    let wall = state.package().input().prices.last().ok_or(Error::Scope)?.wall().exact();
    let bleed =
        crate::constant(frozen.constants(), &profile.bleed_squared, &mut checks.budget)?.exact_string(&mut checks.budget)?;
    let strength = Rational::parse(rung, &mut checks.budget)?;
    if profile.inverse_wall && bound.enclosed_wall().is_none() && !strength.is_zero() && !point.is_empty() {
        return Err(crate::fence::Error::ReferenceWall.into());
    }
    let depth = state.view().support.by_depth.keys().next_back().copied().unwrap_or(0);
    let exponents = profile
        .shape
        .iter()
        .take(depth)
        .map(|name| {
            Ok(strength
                .mul(
                    &crate::constant(frozen.constants(), name, &mut checks.budget)?,
                    &mut checks.budget,
                )?
                .exact_string(&mut checks.budget)?)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    for value in point.values() {
        if Rational::parse(value, &mut checks.budget)?.is_negative() {
            return Err(Error::Scope);
        }
    }
    let powers = if strength.is_zero() {
        vec![vec![singleton("1", &mut checks.budget)?; point.len()]; exponents.len()]
    } else {
        let values = activations(&mut checks, point, wall, &bleed, bound.enclosed_wall())?;
        powers(&mut checks, &values, &exponents)?
    };
    let input = inputs(bound, &mut checks, &powers)?;
    let before = checks.budget.usage().work;
    let maximum_cells =
        usize::try_from(checks.policy.enclosure.as_ref().ok_or(Error::Scope)?.operation.proof_nodes).map_err(|_| Error::Scope)?;
    let output = pn_graph::transport::enclosed::evaluate(&input, &mut checks.budget, maximum_cells)?;
    let actors: Vec<_> = point.keys().cloned().collect();
    let image = super::image(&output.standing, &actors, &mut checks.budget)?;
    if supplied.is_some_and(|r| {
        r.image != image || r.primitives.len() != checks.records.len() || r.transport_input != input || r.transport != output
    }) {
        return Err(Error::Map);
    }
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
