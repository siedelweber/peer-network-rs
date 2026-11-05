use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Default)]
struct Counts {
    replay: AtomicUsize,
    profile: AtomicUsize,
    next: AtomicUsize,
}

#[derive(Debug)]
struct Observer(Arc<Counts>);

#[derive(Default)]
struct Source(String);
impl tracing::field::Visit for Source {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "source_item" {
            self.0 = value.into();
        }
    }
}
impl tracing::Subscriber for Observer {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut source = Source::default();
        attrs.record(&mut source);
        if source.0 == "publication::disclosures::restore" {
            self.0.profile.fetch_add(1, Ordering::SeqCst);
        } else {
            self.0.replay.fetch_add(1, Ordering::SeqCst);
        }
        tracing::span::Id::from_u64(u64::try_from(self.0.next.fetch_add(1, Ordering::SeqCst)).unwrap() + 1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Claim: In the declared publication fixture, incomplete realization and a changed numeric or procedure limit refuse restoration before any nested instrumented replay operation starts; a successful restoration exercises the same observer.
/// ´claim:admission:disclosure-profile-precedes-restoration-work´
/// ´test:integration:disclosure-profile´
#[test]
fn disclosure_profile() {
    let (closed, carrier, check) = fixture(None);
    let admitted = publication::assemble(&closed, carrier, &check).unwrap();
    let raw = admitted.disclosures();
    let counts = Arc::new(Counts::default());
    tracing::subscriber::with_default(Observer(counts.clone()), || {
        disclosures::restore(raw.clone(), &check).unwrap();
    });
    assert_eq!(counts.profile.load(Ordering::SeqCst), 1);
    assert!(counts.replay.load(Ordering::SeqCst) > 0);
    for field in 0..4 {
        let mut changed = raw.clone();
        match field {
            0 => changed.frames[0].realization.provenance.clear(),
            1 => changed.numeric.comparison_work += 1,
            2 => changed.frames[0].procedure.maximum_products += 1,
            _ => changed.frames[0].procedure.solve.maximum_replay_work += 1,
        }
        counts.profile.store(0, Ordering::SeqCst);
        counts.replay.store(0, Ordering::SeqCst);
        let error = tracing::subscriber::with_default(Observer(counts.clone()), || {
            disclosures::restore(changed, &check).unwrap_err()
        });
        assert!(matches!(error, publication::Error::Structure(reason)
            if reason == if field == 0 { "missing realization disclosure" } else { "publication profile" }));
        assert_eq!(counts.profile.load(Ordering::SeqCst), 1);
        assert_eq!(counts.replay.load(Ordering::SeqCst), 0);
    }
}

/// Claim: In the finite ridge publication fixture, frame, binding and debit proofs must exactly match the consumer's boundary profile. Changed procedure or depth and Work limits refuse with their typed profile cause before any nested replay span; matching disclosures restore with all evidence retained and observed replay.
/// ´claim:admission:ridge-disclosures-use-consumer-profile´
/// ´test:integration:ridge-disclosure-profile´
#[test]
fn ridge_disclosure_profile() {
    let evidence = proof(NumberId::NumbersRidgeCertificatePrecision);
    let (closed, carrier, check) = fixture(Some(&evidence));
    let admitted = publication::assemble(&closed, carrier.clone(), &check).unwrap();
    let raw = admitted.disclosures();
    let counts = Arc::new(Counts::default());
    let restored = tracing::subscriber::with_default(Observer(counts.clone()), || {
        disclosures::restore(raw.clone(), &check).unwrap()
    });
    assert_eq!(restored.disclosures(), raw);
    assert_eq!(counts.profile.load(Ordering::SeqCst), 1);
    assert!(counts.replay.load(Ordering::SeqCst) > 0);
    for section in 0..3 {
        for field in 0..7 {
            let mut changed = raw.clone();
            let frame = &mut changed.frames[0];
            let price = match section {
                0 => &mut frame.price,
                1 => &mut frame.closure.bindings[0].price,
                _ => &mut frame.compiled.ledger.debits.values_mut().next().unwrap().price,
            };
            let proof = price.ridge.as_mut().unwrap();
            if field == 0 {
                proof.procedure.maximum_replay_work += 1;
            } else {
                let input = if field <= 3 {
                    &mut proof.input
                } else {
                    &mut proof.record.input
                };
                match (field - 1) % 3 {
                    0 => input.maximum_depth += 1,
                    1 => input.maximum_work += 1,
                    _ => input.maximum_replay_work += 1,
                }
            }
            assert_ne!(changed, raw);
            counts.profile.store(0, Ordering::SeqCst);
            counts.replay.store(0, Ordering::SeqCst);
            let error = tracing::subscriber::with_default(Observer(counts.clone()), || {
                disclosures::restore(changed, &check).unwrap_err()
            });
            let expected = if field == 0 {
                publication::RidgeProfileError::Procedure
            } else {
                publication::RidgeProfileError::Limits
            };
            assert!(matches!(error, publication::Error::RidgeProfile(actual) if actual == expected));
            assert_eq!(counts.profile.load(Ordering::SeqCst), 1);
            assert_eq!(counts.replay.load(Ordering::SeqCst), 0);
        }
    }
    let denied = Check {
        ridge_profiles: std::collections::BTreeMap::new(),
        ..check.clone()
    };
    assert!(matches!(
        disclosures::restore(raw, &denied),
        Err(publication::Error::RidgeProfile(publication::RidgeProfileError::Missing))
    ));
    let mut changed = carrier;
    changed.frames[0].price.ridge.as_mut().unwrap().input.maximum_replay_work += 1;
    assert!(matches!(
        publication::consume(changed, &check),
        Err(publication::Error::RidgeProfile(publication::RidgeProfileError::Limits))
    ));
}
