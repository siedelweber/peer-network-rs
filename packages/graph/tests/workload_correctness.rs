#[path = "../benches/support/mod.rs"]
mod inputs;

/// Claim: Seeded whole-act partition recipes retain requested sizes and independently predicted covers, blocks and intersections.
/// ´claim:membership:workload-partition-inputs-retain-counts-and-cover´
/// ´test:integration:partition-inputs´
#[test]
fn partition_inputs() {
    for seed in [inputs::SEED, 1, 2] {
        for shape in 0..3 {
            inputs::check_partition(seed, 8, shape);
        }
    }
}

/// Claim: Singleton endpoint transport agrees with exact transport and an independent regular-column mean, while a zero cell ceiling refuses.
/// ´claim:numerics:workload-transport-inputs-agree-with-column-oracle´
/// ´test:integration:transport-inputs´
#[test]
fn transport_inputs() {
    for seed in [inputs::SEED, 1, 2] {
        for dense in [false, true] {
            inputs::check_transport(seed, 2, dense).unwrap();
        }
    }
}

/// Claim: Generated title histories retain exact act counts and alternating owners; a wrong-party handshake binds no transfer.
/// ´claim:formation:workload-title-inputs-retain-transfer-oracle´
/// ´test:integration:workload-title-inputs´
#[test]
fn workload_title_inputs() {
    for seed in [inputs::SEED, 1, 2] {
        inputs::check_title(seed, 4);
    }
}

/// Claim: The separately bounded dense sixteen-Actor oracle agrees with the exact operation; the former oracle allowance still refuses with its exhausted Work cause.
/// ´claim:numerics:scaling-transport-oracle-retains-limit-control´
/// ´test:integration:scaling-transport-oracle´
#[test]
fn scaling_transport_oracle() {
    inputs::check_transport(0, 16, true).unwrap();
    let input = inputs::enclosed(&inputs::transport(0, 16, true).unwrap()).unwrap();
    let mut b = nrz_cas::limits::Budget::new(nrz_cas::limits::Limits::default()).unwrap();
    let error = pn_graph::transport::enclosed::evaluate(&input, &mut b, inputs::CELLS).unwrap_err();
    let pn_records::transport::KernelError::Arithmetic(message) = error else {
        panic!("unexpected refusal: {error:?}");
    };
    assert!(message.contains("Work"));
    assert!(message.contains("2000000"));
    assert!(message.contains("2000021"));
}

/// Claim: The dense transport fixture builders return the original typed Work exhaustion instead of panicking at construction or interval conversion.
/// ´claim:numerics:workload-transport-builders-retain-resource-causes´
/// ´test:integration:transport-construction-refusals´
#[test]
fn transport_construction_refusals() {
    let large = inputs::transport(0, 128, true).unwrap_err();
    assert!(matches!(
        large.kind,
        nrz_cas::FaultKind::Exhausted {
            budget: nrz_cas::limits::BudgetKind::Work,
            ..
        }
    ));
    let input = inputs::transport(0, 64, true).unwrap();
    let convert = inputs::enclosed(&input).unwrap_err();
    assert!(matches!(
        convert.kind,
        nrz_cas::FaultKind::Exhausted {
            budget: nrz_cas::limits::BudgetKind::Work,
            ..
        }
    ));
    inputs::enclosed(&inputs::transport(0, 2, true).unwrap()).unwrap();
}

/// Claim: Applied sparse chains and hubs enclose the independent exact matrix oracle with H times Z support visits and linear scratch; insufficient denominator precision refuses.
/// ´claim:numerics:applied-transport-retains-sparse-certified-scope´
/// ´test:integration:applied-transport-agreement´
#[test]
fn applied_transport_agreement() {
    use nrz_cas::{
        Rational,
        enclosure::Interval,
        limits::{Budget, Limits},
    };
    use pn_records::transport::TransportInput;
    use std::collections::BTreeMap;
    let limits = Limits {
        work: 2_000_000_000,
        arithmetic_steps: 100_000_000,
        ..Limits::default()
    };
    let mut b = Budget::new(limits).unwrap();
    let one = Interval::singleton(&Rational::parse("1", &mut b).unwrap(), &mut b).unwrap();
    let zero = Interval::singleton(&Rational::parse("0", &mut b).unwrap(), &mut b).unwrap();
    for n in [4usize, 16] {
        for hub in [false, true] {
            let h = if hub { 2 } else { n };
            let rows: Vec<_> = (0..n)
                .map(|i| {
                    let mut row = BTreeMap::from([(i, one.clone())]);
                    if hub {
                        if i == 0 {
                            row.extend((0..n).map(|j| (j, one.clone())));
                        } else {
                            row.insert(0, one.clone());
                        }
                    } else if i + 1 < n {
                        row.insert(i + 1, one.clone());
                    }
                    row
                })
                .collect();
            let z = rows.iter().map(BTreeMap::len).sum::<usize>();
            let mut masses = vec![zero.clone(); h];
            masses[h - 1] = one.clone();
            let counts = vec![one.clone(); n];
            let rates: Vec<_> = (1..=n)
                .map(|i| Interval::singleton(&Rational::parse(&i.to_string(), &mut b).unwrap(), &mut b).unwrap())
                .collect();
            let input = TransportInput {
                hops: vec![rows.clone(); h],
                depth_mass: masses.clone(),
                emission: counts.clone(),
                counts: counts.clone(),
                rates: rates.clone(),
            };
            let old = pn_graph::transport::enclosed::evaluate(&input, &mut b, n * n * (h + 3)).unwrap();
            let fresh = pn_graph::transport::applied::evaluate(
                &pn_graph::transport::applied::Input {
                    rows: &rows,
                    depth_mass: &masses,
                    emission: &counts,
                    counts: &counts,
                    rates: &rates,
                },
                32,
                z + 10 * n,
                &mut b,
                &mut UnitFactors(one.clone(), n),
            )
            .unwrap();
            assert_eq!(fresh.support_visits, h * z);
            assert_eq!(fresh.vector_slots, 10 * n);
            assert!(fresh.row_slots <= n);
            assert!(old.raw.iter().map(BTreeMap::len).sum::<usize>() > z);
            for (a, c) in old.standing.iter().zip(&fresh.standing) {
                assert!(!c.lower().compare(a.lower(), &mut b).unwrap().is_gt());
                assert!(!c.upper().compare(a.upper(), &mut b).unwrap().is_lt());
            }
            assert!(
                pn_graph::transport::applied::evaluate(
                    &pn_graph::transport::applied::Input {
                        rows: &rows,
                        depth_mass: &masses,
                        emission: &counts,
                        counts: &counts,
                        rates: &rates
                    },
                    32,
                    z + 10 * n - 1,
                    &mut b,
                    &mut UnitFactors(one.clone(), n)
                )
                .is_err()
            );
        }
    }
    applied_denominator_control(&one, &mut b);
}
fn applied_denominator_control(one: &nrz_cas::enclosure::Interval, b: &mut nrz_cas::limits::Budget) {
    use nrz_cas::{Rational, enclosure::Interval};
    use std::collections::BTreeMap;
    let tiny = Interval::singleton(&Rational::parse("1/1000", b).unwrap(), b).unwrap();
    let rows = vec![BTreeMap::from([(0, one.clone())])];
    assert!(matches!(
        pn_graph::transport::applied::evaluate(
            &pn_graph::transport::applied::Input {
                rows: &rows,
                depth_mass: std::slice::from_ref(one),
                emission: std::slice::from_ref(one),
                counts: &[tiny],
                rates: std::slice::from_ref(one)
            },
            0,
            11,
            b,
            &mut UnitFactors(one.clone(), 1)
        ),
        Err(pn_graph::transport::applied::Error::Indecisive)
    ));
}

#[derive(Debug)]
struct UnitFactors(nrz_cas::enclosure::Interval, usize);
impl pn_graph::transport::applied::HopFactors for UnitFactors {
    fn at(
        &mut self,
        _: usize,
        _: &mut nrz_cas::limits::Budget,
    ) -> Result<Vec<nrz_cas::enclosure::Interval>, pn_graph::transport::applied::Error> {
        Ok(vec![self.0.clone(); self.1])
    }
}
