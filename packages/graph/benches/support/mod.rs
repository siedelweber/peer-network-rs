mod causes;
use causes::{Approval, act, named, stamp};
use nrz_cas::{
    Rational,
    enclosure::Interval,
    limits::{Budget, Limits},
};
use pn_records::transport::{ExactArithmetic, KernelError, TransportInput};
use std::collections::BTreeMap;

pub const SEED: u64 = 0;
pub const CELLS: usize = 1_000_000;
// Oracle is independently bounded and excluded from operation measurements.
pub fn operation_limits() -> Limits {
    Limits {
        work: 2_000_000_000,
        arithmetic_steps: 100_000_000,
        ..Limits::default()
    }
}
pub const ORACLE_WORK: u64 = 20_000_000_000;
pub fn oracle_limits() -> Limits {
    Limits {
        work: ORACLE_WORK,
        arithmetic_steps: 1_000_000_000,
        ..Limits::default()
    }
}

pub fn partition(seed: u64, m: usize, shape: usize) -> pn_records::ValidatedRecords {
    assert!(m > 0 && shape < 3);
    let mut raw: Vec<_> = (0..m)
        .map(|i| act("Opinion", &format!("a{seed}-{i}"), u64::try_from(i).unwrap() + 1, 1))
        .collect();
    for i in 0..raw.len() {
        raw[i].legs[0].target = named("prof", &format!("r{seed}-{i}"));
        let parent = if i == 0 || shape == 0 {
            None
        } else if shape == 1 {
            Some(i - 1)
        } else {
            Some(0)
        };
        if let Some(parent) = parent {
            let id = raw[parent].id.clone();
            raw[i].body.asserted_parents.push(id.clone());
            raw[i].projections.dependency = pn_records::DependencyProjection::Full(vec![id]);
        }
    }
    stamp(&mut raw);
    raw.reverse();
    let history = pn_records::validate_history(&[], &[]).unwrap();
    pn_records::validate_record(&raw, &history, &[]).unwrap()
}

pub fn check_partition(seed: u64, m: usize, shape: usize) {
    let record = partition(seed, m, shape);
    let input = pn_records::assemble_boundary_inputs(&record, (1, 1)).unwrap();
    let (graph, blocks) = pn_graph::partition_dependencies(&input).unwrap();
    assert_eq!(input.acts().len(), m);
    assert_eq!(graph.node_count(), m);
    assert_eq!(blocks.len(), if shape == 0 { m } else { 1 });
    let mut flat: Vec<_> = blocks.into_iter().flatten().collect();
    flat.sort();
    let mut expected: Vec<_> = input.acts().iter().map(|a| a.id().clone()).collect();
    expected.sort();
    assert_eq!(flat, expected);
    assert_eq!(graph.edge_count(), if shape == 0 { 0 } else { m * (m - 1) / 2 });
}

#[derive(Debug)]
pub struct Arithmetic {
    pub budget: Budget,
    zero: Rational,
    one: Rational,
}
impl Arithmetic {
    pub fn new() -> Self {
        Self::with_limits(operation_limits())
    }
    pub fn with_limits(limits: Limits) -> Self {
        let mut budget = Budget::new(limits).unwrap();
        let zero = Rational::parse("0", &mut budget).unwrap();
        let one = Rational::parse("1", &mut budget).unwrap();
        Self { budget, zero, one }
    }
}
fn fault(e: nrz_cas::Fault) -> KernelError {
    KernelError::Arithmetic(e.to_string())
}
impl ExactArithmetic for Arithmetic {
    type Number = Rational;
    fn zero(&self) -> Rational {
        self.zero.clone()
    }
    fn one(&self) -> Rational {
        self.one.clone()
    }
    fn add(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.add(b, &mut self.budget).map_err(fault)
    }
    fn sub(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.sub(b, &mut self.budget).map_err(fault)
    }
    fn mul(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.mul(b, &mut self.budget).map_err(fault)
    }
    fn div(&mut self, a: &Rational, b: &Rational) -> Result<Rational, KernelError> {
        a.div(b, &mut self.budget).map_err(fault)
    }
    fn compare(&mut self, a: &Rational, b: &Rational) -> Result<std::cmp::Ordering, KernelError> {
        a.compare(b, &mut self.budget).map_err(fault)
    }
}
pub fn transport(seed: u64, n: usize, dense: bool) -> Result<TransportInput<Rational>, nrz_cas::Fault> {
    let mut b = Budget::new(Limits::default())?;
    let mut number = |v: u64| Rational::parse(&v.to_string(), &mut b);
    let mut rows = Vec::new();
    for i in 0..n {
        let mut row = BTreeMap::new();
        for j in 0..n {
            if dense || j == i || j == (i + 1) % n {
                row.insert(j, number(1)?);
            }
        }
        rows.push(row);
    }
    Ok(TransportInput {
        hops: vec![rows],
        depth_mass: vec![number(1)?],
        emission: vec![number(1)?; n],
        counts: vec![number(1)?; n],
        rates: (0..n)
            .map(|i| number(2 + ((u64::try_from(i).unwrap() + seed) % n as u64)))
            .collect::<Result<_, _>>()?,
    })
}
pub fn enclosed(input: &TransportInput<Rational>) -> Result<TransportInput<Interval>, nrz_cas::Fault> {
    let mut b = Budget::new(Limits::default())?;
    let mut singleton = |v: &Rational| Interval::singleton(v, &mut b);
    Ok(TransportInput {
        hops: input
            .hops
            .iter()
            .map(|hop| {
                hop.iter()
                    .map(|row| {
                        row.iter()
                            .map(|(k, v)| Ok((*k, singleton(v)?)))
                            .collect::<Result<_, nrz_cas::Fault>>()
                    })
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()?,
        depth_mass: input.depth_mass.iter().map(&mut singleton).collect::<Result<_, _>>()?,
        emission: input.emission.iter().map(&mut singleton).collect::<Result<_, _>>()?,
        counts: input.counts.iter().map(&mut singleton).collect::<Result<_, _>>()?,
        rates: input.rates.iter().map(&mut singleton).collect::<Result<_, _>>()?,
    })
}
pub fn check_transport(seed: u64, n: usize, dense: bool) -> Result<(), KernelError> {
    let input = transport(seed, n, dense).map_err(fault)?;
    let exact = pn_graph::transport::exact_transport(&input, &mut Arithmetic::with_limits(oracle_limits()), CELLS)?;
    let range = pn_graph::transport::enclosed::evaluate(
        &enclosed(&input).map_err(fault)?,
        &mut Budget::new(oracle_limits()).unwrap(),
        CELLS,
    )?;
    let mut b = Budget::new(Limits::default()).unwrap();
    for (i, (v, r)) in exact.standing.iter().zip(&range.standing).enumerate() {
        assert_eq!(v.exact_string(&mut b).unwrap(), r.lower().exact_string(&mut b).unwrap());
        assert_eq!(v.exact_string(&mut b).unwrap(), r.upper().exact_string(&mut b).unwrap());
        // Independent one-hop regular-graph oracle: each column has the same degree.
        let sources: Vec<_> = (0..n).filter(|j| dense || *j == i || (*j + 1) % n == i).collect();
        let sum: u64 = sources
            .iter()
            .map(|j| 2 + ((u64::try_from(*j).unwrap() + seed) % n as u64))
            .sum();
        let oracle = Rational::parse(&format!("{sum}/{}", sources.len()), &mut b).unwrap();
        assert_eq!(v.compare(&oracle, &mut b).unwrap(), std::cmp::Ordering::Equal);
    }
    assert_eq!(
        input.hops[0].iter().map(BTreeMap::len).sum::<usize>(),
        if dense { n * n } else { 2 * n }
    );
    assert_eq!(
        pn_graph::transport::exact_transport(&input, &mut Arithmetic::new(), 0),
        Err(KernelError::Limit)
    );
    Ok(())
}

pub struct Title {
    pub history: pn_records::ValidatedHistory,
    pub graph: pn_graph::formation::FormationGraph,
    pub approval: Approval,
    pub epoch: u64,
    pub item: pn_records::PublicReference,
    pub owner: String,
}
pub fn title(seed: u64, m: usize, wrong_party: bool) -> Title {
    assert!(m >= 4 && (m - 1) % 3 == 0);
    let actors = [format!("owner-{seed}-a"), format!("owner-{seed}-b")];
    let mut genesis = act("Owner", &actors[0], 1, 1);
    causes::coordinates(&mut genesis, &["attachment"], 0);
    let item = pn_records::PublicReference::Minted(genesis.id.clone());
    let mut raw = vec![genesis];
    let transfers = (m - 1) / 3;
    for k in 0..transfers {
        let seller = &actors[k % 2];
        let buyer = &actors[(k + 1) % 2];
        let epoch = u64::try_from(k + 1).unwrap();
        let seq = u64::try_from(2 + 3 * k).unwrap();
        let mut bid = act("Bid", buyer, seq, epoch);
        bid.legs[0].target = item.clone();
        bid.legs[1].source = item.clone();
        let mut accept = act("Accept", seller, seq + 1, epoch);
        accept.legs[0].target = named("addr", if wrong_party && k == 0 { "outsider" } else { buyer });
        accept.body.settlement = Some(pn_records::SettlementReferences::Accept { settles: bid.id.clone() });
        let mut ratify = act("Ratify", buyer, seq + 2, epoch);
        ratify.legs[0].target = named("addr", seller);
        ratify.body.settlement = Some(pn_records::SettlementReferences::Ratify {
            settles: bid.id.clone(),
            accepts: accept.id.clone(),
        });
        raw.extend([bid, accept, ratify]);
    }
    stamp(&mut raw);
    raw.reverse();
    let history = pn_records::validate_history(&raw, &[]).unwrap();
    assert_eq!(history.acts().len(), m);
    let approval = Approval(history.acts().to_vec());
    let graph = pn_graph::formation::reconstruct_replay(&history, &approval).unwrap();
    Title {
        history,
        graph,
        approval,
        epoch: u64::try_from(transfers).unwrap(),
        item,
        owner: actors[transfers % 2].clone(),
    }
}
pub fn check_title(seed: u64, m: usize) {
    let input = title(seed, m, false);
    let result = pn_graph::title::replay_title(&input.graph, &input.history, &input.approval, input.epoch).unwrap();
    assert_eq!(result.certificate.get(&input.item), Some(&Some(input.owner)));
    assert_eq!(result.consumed.len(), m - 1);
    assert_eq!(result.boundaries.len(), (m - 1) / 3);
    let bad = title(seed, 4, true);
    let result = pn_graph::title::replay_title(&bad.graph, &bad.history, &bad.approval, bad.epoch).unwrap();
    assert_eq!(result.consumed.len(), 0);
    assert_ne!(result.certificate.get(&bad.item), Some(&Some(bad.owner)));
}
