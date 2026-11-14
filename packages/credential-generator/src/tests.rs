use super::*;

struct Controlled {
    events: Vec<&'static str>,
    construction: bool,
    password: Result<usize, DeliveryError>,
    verifier: Result<usize, DeliveryError>,
    completion: Result<(), CredentialError>,
}

impl Stages for Controlled {
    fn construct(&mut self) -> Result<(), Failure> {
        self.events.push("construct");
        if self.construction {
            Ok(())
        } else {
            Err(Failure::Construction(CredentialError::Home(pn_secret_home::Error::Entropy)))
        }
    }
    fn password(&mut self) -> Result<usize, DeliveryError> {
        self.events.push("password");
        self.password
    }
    fn verifier(&mut self) -> Result<usize, DeliveryError> {
        self.events.push("verifier");
        self.verifier
    }
    fn complete(&mut self) -> Result<(), CredentialError> {
        self.events.push("complete");
        self.completion
    }
}

/// The production terminal driver checks construction before either delivery,
/// attempts both deliveries and completion despite refusal, rejects partial output
/// and full output with failed completion, and performs no later stage callback.
/// ´claim:generator:terminal-driver-checks-every-stage-before-exit´
/// ´test:unit:lifecycle´
#[test]
fn lifecycle() {
    let mut cases = Vec::new();
    for construction in [true, false] {
        for password in [
            Ok(64),
            Ok(63),
            Err(DeliveryError {
                accepted: 7,
                kind: pn_secret_home::DeliveryFailure::Write,
            }),
        ] {
            for verifier in [
                Ok(135),
                Ok(134),
                Err(DeliveryError {
                    accepted: 0,
                    kind: pn_secret_home::DeliveryFailure::ClosedReader,
                }),
            ] {
                for completion in [Ok(()), Err(CredentialError::Completion)] {
                    cases.push(Controlled {
                        events: Vec::new(),
                        construction,
                        password,
                        verifier,
                        completion,
                    });
                }
            }
        }
    }
    assert_eq!(cases.len(), 36, "distinct stage outcome tuples");
    for mut stages in cases {
        let result = terminal(&mut stages);
        let success = stages.construction && stages.password == Ok(64) && stages.verifier == Ok(135) && stages.completion.is_ok();
        assert_eq!(result.is_ok(), success, "only exact streams with checked completion succeed");
        assert_eq!(
            stages.events,
            if stages.construction {
                vec!["construct", "password", "verifier", "complete"]
            } else {
                vec!["construct"]
            },
            "terminal lifecycle has no later work or skipped completion"
        );
        if let Err(error) = result {
            assert!(std::error::Error::source(&error).is_none(), "no private source chain");
            assert!(!error.to_string().is_empty(), "public refusal retained");
        }
    }
}
