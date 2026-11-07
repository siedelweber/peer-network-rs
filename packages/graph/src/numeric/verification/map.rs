//! Reconstructed scalar queries and finite-depth box transport.
//! (´[ROOT-alg:design:transport]´)
use super::{Error, arithmetic::Arithmetic, budget};
use crate::numeric::activation::{self, Quantity, Request};
use nrz_cas::{Location, Rational, enclosure::Interval};
use pn_records::{
    conserved::{BoxMapRecord, VerificationInput},
    primitive::{Goal, Node, PrimitiveRecord, Query, Range},
    solve::Procedure,
};
use std::collections::BTreeSet;

pub(super) struct Engine<'arithmetic> {
    pub arithmetic: Arithmetic,
    pub policy: &'arithmetic Procedure,
    pub supplied: Option<&'arithmetic [PrimitiveRecord]>,
    pub records: Vec<PrimitiveRecord>,
}
impl Engine<'_> {
    pub(super) fn query(&mut self, query: Query) -> Result<Interval, Error> {
        let precision = self.policy.enclosure.as_ref().ok_or(Error::Declaration)?.refinement.precision;
        let mut policy = self.policy.clone();
        let available = policy
            .enclosure
            .as_ref()
            .ok_or(Error::Declaration)?
            .operation
            .work
            .checked_sub(self.arithmetic.budget.usage().work)
            .ok_or(Error::Declaration)?;
        policy.enclosure.as_mut().ok_or(Error::Declaration)?.operation.work = available;
        let evidence = if let Some(supplied) = self.supplied {
            let record = supplied.get(self.records.len()).ok_or(Error::Declaration)?;
            if record.query != query || record.precision != precision {
                return Err(Error::Declaration);
            }
            crate::numeric::replay(
                &policy,
                &query,
                record.evidence.attachment.as_ref().ok_or(Error::Declaration)?,
                None,
            )?
        } else {
            crate::numeric::evaluate(&policy, &query, None)?
        };
        if let Some(fault) = &evidence.resource_fault {
            return Err(Error::Resource(fault.clone()));
        }
        self.arithmetic
            .budget
            .work(evidence.work, Location::new("verification scalar"))?;
        if evidence.attachment.is_none() {
            return Err(Error::Declaration);
        }
        let value = evidence.bounds.clone().ok_or(Error::Declaration)?;
        self.records.push(PrimitiveRecord {
            query,
            precision,
            evidence,
        });
        Ok(value)
    }
}

pub(super) struct Prepared {
    pub rates: Vec<Interval>,
    pub counts: Vec<Interval>,
    pub base: Vec<Vec<Interval>>,
    pub support: Vec<BTreeSet<usize>>,
    pub hull: Vec<Range>,
    pub inner_hull: Vec<Range>,
    pub fence: Range,
    pub contraction: String,
}

fn validate(engine: &mut Engine<'_>, input: &VerificationInput) -> Result<(Interval, Rational), Error> {
    let size = input.sources.len();
    let depth = input.shape.len();
    let policy = engine.policy.enclosure.as_ref().ok_or(Error::Declaration)?;
    let maximum = usize::try_from(policy.operation.proof_nodes).map_err(|_| Error::Declaration)?;
    if size == 0
        || depth == 0
        || depth != input.depth_mass.len()
        || input.endpoint_bits == 0
        || input.endpoint_bits > policy.refinement.grid_ceiling
        || size
            .checked_mul(size)
            .and_then(|v| v.checked_mul(depth + 3))
            .is_none_or(|v| v > maximum)
    {
        return Err(Error::Declaration);
    }
    let arithmetic = &mut engine.arithmetic;
    let one = arithmetic.scalar("1")?;
    let wall = arithmetic.range(&input.wall)?;
    let k = policy.refinement.reduction_ceiling;
    let scale = 1_u64.checked_shl(k).filter(|v| *v > 2).ok_or(Error::Declaration)?;
    let minimum = Rational::parse("1", &mut arithmetic.budget)?.div(
        &Rational::parse(&(scale - 2).to_string(), &mut arithmetic.budget)?,
        &mut arithmetic.budget,
    )?;
    if wall.lower().compare(&minimum, &mut arithmetic.budget)?.is_lt() {
        return Err(Error::Declaration);
    }
    let strength = Rational::parse(&input.strength, &mut arithmetic.budget)?;
    if strength.is_negative() {
        return Err(Error::Declaration);
    }
    let mut mass = Rational::parse("0", &mut arithmetic.budget)?;
    let mut cumulative = Rational::parse("0", &mut arithmetic.budget)?;
    let mut supported = 0;
    let mut previous: Option<Rational> = None;
    for (i, (shape, weight)) in input.shape.iter().zip(&input.depth_mass).enumerate() {
        let shape = Rational::parse(shape, &mut arithmetic.budget)?;
        let weight = Rational::parse(weight, &mut arithmetic.budget)?;
        if shape.is_negative()
            || weight.is_negative()
            || previous
                .as_ref()
                .map(|v| shape.compare(v, &mut arithmetic.budget))
                .transpose()?
                .is_some_and(std::cmp::Ordering::is_gt)
        {
            return Err(Error::Declaration);
        }
        previous = Some(shape.clone());
        cumulative = cumulative.add(&shape, &mut arithmetic.budget)?;
        mass = mass.add(&weight, &mut arithmetic.budget)?;
        if !weight.is_zero() {
            supported = i + 1;
        }
    }
    if mass != *one.lower() || supported != depth {
        return Err(Error::Declaration);
    }
    cumulative = cumulative.mul(&strength, &mut arithmetic.budget)?;
    Ok((wall, cumulative))
}

fn sources(engine: &mut Engine<'_>, input: &VerificationInput, wall: &Interval) -> Result<(Vec<Interval>, Vec<Interval>), Error> {
    let arithmetic = &mut engine.arithmetic;
    let mut names = BTreeSet::new();
    let mut rates = Vec::new();
    let mut counts = Vec::new();
    for source in &input.sources {
        if !names.insert(&source.name) {
            return Err(Error::Declaration);
        }
        let count = arithmetic.scalar(&source.count)?;
        if count.lower().is_negative() || count.lower().is_zero() {
            return Err(Error::Declaration);
        }
        let intercept = arithmetic.scalar(&source.intercept)?;
        let slope = arithmetic.scalar(&source.slope)?;
        let varying = arithmetic.mul(&slope, wall)?;
        let rate = arithmetic.add(&intercept, &varying)?;
        if !rate.lower().compare(wall.upper(), &mut arithmetic.budget)?.is_gt() {
            return Err(Error::Declaration);
        }
        counts.push(count);
        rates.push(rate);
    }
    Ok((rates, counts))
}

fn base(engine: &mut Engine<'_>, input: &VerificationInput) -> Result<Vec<Vec<Interval>>, Error> {
    let size = input.sources.len();
    let arithmetic = &mut engine.arithmetic;
    let zero = arithmetic.scalar("0")?;
    let retention = arithmetic.scalar(&input.retention)?;
    if retention.lower().is_negative() || retention.lower().is_zero() {
        return Err(Error::Declaration);
    }
    let mut base = vec![vec![zero; size]; size];
    for (i, row) in base.iter_mut().enumerate() {
        row[i] = retention.clone();
    }
    let mut edges = BTreeSet::new();
    for edge in &input.edges {
        let u = input
            .sources
            .iter()
            .position(|v| v.name == edge.source)
            .ok_or(Error::Declaration)?;
        let v = input
            .sources
            .iter()
            .position(|v| v.name == edge.target)
            .ok_or(Error::Declaration)?;
        if u == v || !edges.insert((u, v)) {
            return Err(Error::Declaration);
        }
        let q = Query {
            coordinates: Vec::new(),
            nodes: vec![Node::Rational(edge.radicand.clone()), Node::SquareRoot(0)],
            target: 1,
            goal: Goal::Width,
        };
        base[u][v] = engine.query(q)?;
        if base[u][v].lower().is_negative() || base[u][v].lower().is_zero() {
            return Err(Error::Declaration);
        }
    }
    Ok(base)
}

fn support(engine: &mut Engine<'_>, input: &VerificationInput, base: &[Vec<Interval>]) -> Result<Vec<BTreeSet<usize>>, Error> {
    let size = input.sources.len();
    let mut support: Vec<_> = (0..size).map(|i| BTreeSet::from([i])).collect();
    for u in 0..size {
        let mut reached = BTreeSet::from([u]);
        for weight in &input.depth_mass {
            reached = reached
                .iter()
                .flat_map(|i| {
                    base[*i]
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| !v.upper().is_zero())
                        .map(|(j, _)| j)
                })
                .collect();
            if !Rational::parse(weight, &mut engine.arithmetic.budget)?.is_zero() {
                for target in &reached {
                    support[*target].insert(u);
                }
            }
        }
    }
    Ok(support)
}

fn hulls(
    engine: &mut Engine<'_>,
    input: &VerificationInput,
    rates: &[Interval],
    support: &[BTreeSet<usize>],
    wall: &Interval,
) -> Result<(Vec<Range>, Vec<Range>, Rational), Error> {
    let arithmetic = &mut engine.arithmetic;
    let mut hull = Vec::new();
    let mut inner = Vec::new();
    let mut width = Rational::parse("0", &mut arithmetic.budget)?;
    for sources in support {
        let mut lower = rates[*sources.first().ok_or(Error::Declaration)?].lower().clone();
        let mut upper = lower.clone();
        let mut inner_lower = rates[*sources.first().ok_or(Error::Declaration)?].upper().clone();
        let mut inner_upper = lower.clone();
        for u in sources {
            if rates[*u].upper().compare(&inner_lower, &mut arithmetic.budget)?.is_lt() {
                inner_lower = rates[*u].upper().clone();
            }
            if rates[*u].lower().compare(&inner_upper, &mut arithmetic.budget)?.is_gt() {
                inner_upper = rates[*u].lower().clone();
            }
            if rates[*u].lower().compare(&lower, &mut arithmetic.budget)?.is_lt() {
                lower = rates[*u].lower().clone();
            }
            if rates[*u].upper().compare(&upper, &mut arithmetic.budget)?.is_gt() {
                upper = rates[*u].upper().clone();
            }
            for v in sources {
                let left = arithmetic.scalar(&input.sources[*u].intercept)?;
                let right = arithmetic.scalar(&input.sources[*v].intercept)?;
                let intercept = arithmetic.sub(&left, &right)?;
                let left = arithmetic.scalar(&input.sources[*u].slope)?;
                let right = arithmetic.scalar(&input.sources[*v].slope)?;
                let slope = arithmetic.sub(&left, &right)?;
                let variable = arithmetic.mul(&slope, wall)?;
                let gap = arithmetic.add(&intercept, &variable)?;
                if gap.upper().compare(&width, &mut arithmetic.budget)?.is_gt() {
                    width = gap.upper().clone();
                }
            }
        }
        inner.push(Range {
            lower: inner_lower.exact_string(&mut arithmetic.budget)?,
            upper: inner_upper.exact_string(&mut arithmetic.budget)?,
        });
        hull.push(Range {
            lower: lower.exact_string(&mut arithmetic.budget)?,
            upper: upper.exact_string(&mut arithmetic.budget)?,
        });
    }
    Ok((hull, inner, width))
}

pub(super) fn prepare(engine: &mut Engine<'_>, input: &VerificationInput) -> Result<Prepared, Error> {
    let (wall, cumulative) = validate(engine, input)?;
    let (rates, counts) = sources(engine, input, &wall)?;
    let base = base(engine, input)?;
    let support = support(engine, input, &base)?;
    let (hull, inner_hull, width) = hulls(engine, input, &rates, &support, &wall)?;
    let arithmetic = &mut engine.arithmetic;
    let one = arithmetic.scalar("1")?;
    let fence_input = activation::fence::Inputs {
        wall: input.wall.lower.clone(),
        bleed_squared: "1/400".into(),
        width: width.exact_string(&mut arithmetic.budget)?,
        margin: engine.policy.margin.clone(),
        cumulative_tilt: cumulative.exact_string(&mut arithmetic.budget)?,
    };
    let query = activation::fence::query(engine.policy, &fence_input)?;
    let fence = engine.query(query)?;
    let arithmetic = &mut engine.arithmetic;
    if fence.upper().compare(one.upper(), &mut arithmetic.budget)?.is_gt() {
        return Err(Error::Declaration);
    }
    let margin = Rational::parse(&engine.policy.margin, &mut arithmetic.budget)?;
    if !margin.compare(one.upper(), &mut arithmetic.budget)?.is_gt() {
        return Err(Error::Declaration);
    }
    let contraction = fence
        .upper()
        .div(&margin, &mut arithmetic.budget)?
        .exact_string(&mut arithmetic.budget)?;
    Ok(Prepared {
        rates,
        counts,
        base,
        support,
        hull,
        inner_hull,
        fence: arithmetic.encode(&fence)?,
        contraction,
    })
}

pub(super) fn image(
    engine: &mut Engine<'_>,
    input: &VerificationInput,
    coordinates: &[Range],
    prepared: &Prepared,
) -> Result<Vec<Range>, Error> {
    let size = input.sources.len();
    if coordinates.len() != size {
        return Err(Error::Declaration);
    }
    let zero = engine.arithmetic.scalar("0")?;
    let one = engine.arithmetic.scalar("1")?;
    let mut product = vec![vec![zero.clone(); size]; size];
    for (i, row) in product.iter_mut().enumerate() {
        row[i] = one.clone();
    }
    let mut mixture = vec![vec![zero.clone(); size]; size];
    for (shape, mass) in input.shape.iter().zip(&input.depth_mass) {
        let mut values = Vec::new();
        for coordinate in coordinates {
            let request = Request {
                standing: coordinate.clone(),
                bleed_squared: "1/400".into(),
                wall: None,
                wall_enclosure: Some(input.wall.clone()),
                quantity: Quantity::Hop {
                    strength: input.strength.clone(),
                    shape: shape.clone(),
                },
            };
            let query = activation::query(&request, &mut engine.arithmetic.budget)?;
            values.push(engine.query(query)?);
        }
        let arithmetic = &mut engine.arithmetic;
        let mut hop = prepared.base.clone();
        for (i, row) in hop.iter_mut().enumerate() {
            let mut sum = zero.clone();
            for (j, value) in row.iter_mut().enumerate() {
                if i != j {
                    *value = arithmetic.mul(value, &values[j])?;
                }
                sum = arithmetic.add(&sum, value)?;
            }
            for value in row {
                *value = arithmetic.div(value, &sum)?;
            }
        }
        let mut next = vec![vec![zero.clone(); size]; size];
        for (u, row) in product.iter().enumerate() {
            for (j, out) in next[u].iter_mut().enumerate() {
                for (k, value) in row.iter().enumerate() {
                    let term = arithmetic.mul(value, &hop[k][j])?;
                    *out = arithmetic.add(out, &term)?;
                }
            }
        }
        product = next;
        let mass = arithmetic.scalar(mass)?;
        for (u, row) in mixture.iter_mut().enumerate() {
            for (j, value) in row.iter_mut().enumerate() {
                let term = arithmetic.mul(&product[u][j], &mass)?;
                *value = arithmetic.add(value, &term)?;
            }
        }
    }
    let arithmetic = &mut engine.arithmetic;
    let mut result = Vec::new();
    for (j, sources) in prepared.support.iter().enumerate() {
        if sources.len() == 1 {
            result.push(arithmetic.encode(&prepared.rates[j])?);
            continue;
        }
        let mut numerator = zero.clone();
        let mut denominator = zero.clone();
        for (u, row) in mixture.iter().enumerate() {
            let count = arithmetic.mul(&row[j], &prepared.counts[u])?;
            denominator = arithmetic.add(&denominator, &count)?;
            let weighted = arithmetic.mul(&count, &prepared.rates[u])?;
            numerator = arithmetic.add(&numerator, &weighted)?;
        }
        let value = arithmetic.div(&numerator, &denominator)?;
        let hull = arithmetic.range(&prepared.hull[j])?;
        let enclosed = value.intersection(&hull, &mut arithmetic.budget)?;
        result.push(arithmetic.encode(&enclosed)?);
    }
    Ok(result)
}

pub(super) fn run(
    p: &Procedure,
    input: &VerificationInput,
    coordinates: &[Range],
    supplied: Option<&BoxMapRecord>,
) -> Result<BoxMapRecord, Error> {
    let mut engine = Engine {
        arithmetic: Arithmetic {
            budget: budget(p)?,
            bits: input.endpoint_bits,
        },
        policy: p,
        supplied: supplied.map(|r| r.primitives.as_slice()),
        records: Vec::new(),
    };
    let prepared = prepare(&mut engine, input)?;
    let image = image(&mut engine, input, coordinates, &prepared)?;
    let result = BoxMapRecord {
        input: input.clone(),
        coordinates: coordinates.to_vec(),
        image,
        hull: prepared.hull,
        inner_hull: prepared.inner_hull,
        singleton: prepared.support.iter().map(|v| v.len() == 1).collect(),
        support: prepared.support.iter().map(|v| v.iter().copied().collect()).collect(),
        fence: prepared.fence,
        contraction: prepared.contraction,
        primitives: engine.records,
        work: engine.arithmetic.budget.usage().work,
    };
    if supplied.is_some_and(|r| {
        r.image != result.image
            || r.hull != result.hull
            || r.inner_hull != result.inner_hull
            || r.singleton != result.singleton
            || r.support != result.support
            || r.fence != result.fence
            || r.contraction != result.contraction
            || r.primitives.len() != result.primitives.len()
    }) {
        return Err(Error::Declaration);
    }
    Ok(result)
}
