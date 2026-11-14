//! Finite administrator publication model; no filesystem or secret material.
//! (´crit:generator:publication´)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Authorization {
    Missing,
    Initial,
    Rotation,
    Consumed,
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Generating,
    Staged,
    Linked(u8),
    Marker,
    Complete,
    SelectionStaged,
    SelectionReady,
    Selected,
    Active,
    Discarded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Evidence {
    Missing,
    Present,
}

impl Evidence {
    fn from_flag(value: bool) -> Self {
        if value { Self::Present } else { Self::Missing }
    }

    fn present(self) -> bool {
        self == Self::Present
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct References {
    instance: u8,
    creation: u8,
    predecessor: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    authorization: Authorization,
    expected: References,
    authorized: References,
    marker: Option<References>,
    rotation: bool,
    admissible: Evidence,
    predecessor: Evidence,
    selected_predecessor: Evidence,
    store_empty: bool,
    retained: bool,
    phase: Phase,
    generations: u8,
    synced: Evidence,
    equal: Evidence,
    drained: Evidence,
    checked: Evidence,
    ready: Evidence,
    disposal_record: Evidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Generate,
    Receive(Receipt),
    Sync,
    Link,
    Marker,
    StageSelection,
    Select,
    Consume,
    Start,
    Discard,
    RecordDisposal,
    Recover,
}

impl State {
    fn initial(rotation: bool) -> Self {
        let expected = References {
            instance: 1,
            creation: 2,
            predecessor: rotation.then_some(1),
        };
        Self {
            authorization: if rotation {
                Authorization::Rotation
            } else {
                Authorization::Initial
            },
            expected,
            authorized: expected,
            marker: None,
            rotation,
            admissible: Evidence::Present,
            predecessor: Evidence::from_flag(rotation),
            selected_predecessor: Evidence::from_flag(rotation),
            store_empty: !rotation,
            retained: false,
            phase: Phase::Empty,
            generations: 0,
            synced: Evidence::Missing,
            equal: Evidence::Missing,
            drained: Evidence::Missing,
            checked: Evidence::Missing,
            ready: Evidence::Missing,
            disposal_record: Evidence::Missing,
        }
    }

    fn apply(self, event: Event) -> Option<Self> {
        match event {
            Event::Generate | Event::Receive(_) | Event::Sync | Event::Link | Event::Marker => self.publication(event),
            Event::StageSelection | Event::Select | Event::Consume | Event::Start => self.activation(event),
            Event::Discard | Event::RecordDisposal => self.disposal(event),
            Event::Recover => self.recovery(),
        }
    }

    fn publication(self, event: Event) -> Option<Self> {
        let mut next = self;
        match event {
            Event::Generate => {
                let class = if self.rotation {
                    Authorization::Rotation
                } else {
                    Authorization::Initial
                };
                if self.authorization != class
                    || self.authorized != self.expected
                    || !self.admissible.present()
                    || self.predecessor.present() != self.rotation
                    || self.selected_predecessor.present() != self.rotation
                    || self.store_empty == self.rotation
                    || self.retained
                    || self.phase != Phase::Empty
                {
                    return None;
                }
                next.phase = Phase::Generating;
                next.generations += 1;
            }
            Event::Receive(receipt) => {
                if self.phase != Phase::Generating || !accepts(receipt.invocations, receipt.measures) {
                    return None;
                }
                next.phase = Phase::Staged;
                next.synced = Evidence::Missing;
            }
            Event::Sync => {
                next.synced = Evidence::Present;
                if self.phase == Phase::Marker {
                    next.phase = Phase::Complete;
                }
                if self.phase == Phase::SelectionStaged {
                    next.phase = Phase::SelectionReady;
                }
            }
            Event::Link => {
                if !self.synced.present() {
                    return None;
                }
                next.phase = match self.phase {
                    Phase::Staged => Phase::Linked(1),
                    Phase::Linked(n) if n < 4 => Phase::Linked(n + 1),
                    _ => return None,
                };
                next.synced = Evidence::Missing;
            }
            Event::Marker => {
                if self.phase != Phase::Linked(4) || !self.synced.present() {
                    return None;
                }
                next.phase = Phase::Marker;
                next.marker = Some(self.expected);
                next.synced = Evidence::Missing;
            }
            _ => return None,
        }
        Some(next)
    }

    fn activation(self, event: Event) -> Option<Self> {
        let mut next = self;
        match event {
            Event::StageSelection => {
                if self.phase != Phase::Complete
                    || self.marker != Some(self.expected)
                    || !self.synced.present()
                    || (self.rotation && (!self.equal.present() || !self.drained.present()))
                {
                    return None;
                }
                next.phase = Phase::SelectionStaged;
                next.synced = Evidence::Missing;
            }
            Event::Select => {
                if self.phase != Phase::SelectionReady
                    || !self.synced.present()
                    || (self.rotation && (!self.equal.present() || !self.drained.present()))
                {
                    return None;
                }
                next.phase = Phase::Selected;
                next.synced = Evidence::Missing;
            }
            Event::Consume => {
                if self.phase != Phase::Selected
                    || !self.synced.present()
                    || (self.rotation && (!self.equal.present() || !self.checked.present()))
                {
                    return None;
                }
                next.authorization = Authorization::Consumed;
                next.synced = Evidence::Missing;
                next.retained = self.rotation;
            }
            Event::Start => {
                if self.authorization != Authorization::Consumed
                    || self.phase != Phase::Selected
                    || !self.synced.present()
                    || !self.equal.present()
                    || !self.checked.present()
                {
                    return None;
                }
                next.phase = Phase::Active;
            }
            _ => return None,
        }
        Some(next)
    }

    fn disposal(self, event: Event) -> Option<Self> {
        let mut next = self;
        match event {
            Event::Discard => {
                if !self.retained
                    || !self.ready.present()
                    || self.phase != Phase::Active
                    || !self.disposal_record.present()
                    || !self.synced.present()
                {
                    return None;
                }
                next.retained = false;
                next.phase = Phase::Discarded;
            }
            Event::RecordDisposal => {
                if !self.retained || !self.ready.present() || self.phase != Phase::Active {
                    return None;
                }
                next.disposal_record = Evidence::Present;
                next.synced = Evidence::Missing;
            }
            _ => return None,
        }
        Some(next)
    }

    fn recovery(self) -> Option<Self> {
        let mut next = self;
        if matches!(
            self.phase,
            Phase::Generating | Phase::Staged | Phase::Linked(_) | Phase::Marker
        ) {
            let class = if self.rotation {
                Authorization::Rotation
            } else {
                Authorization::Initial
            };
            if self.authorization != class || self.authorized != self.expected {
                return None;
            }
            next.phase = Phase::Empty;
            next.marker = None;
            next.synced = Evidence::Missing;
            if self.rotation {
                if !self.equal.present() || !self.predecessor.present() || !self.selected_predecessor.present() {
                    return None;
                }
                next.authorization = Authorization::Abandoned;
            }
        }
        Some(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    Pending,
    Ended,
    UnlinkSource,
    AbsentCandidate,
    Refuse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndingPurpose {
    File,
    Superseded { set: u8, recorded: Option<u8>, durable: bool },
    IncompleteCandidate,
}

fn ending(source: Option<Identity>, destination: Option<Identity>, purpose: EndingPurpose) -> Ending {
    match (source, destination) {
        (Some(_), None) => Ending::Pending,
        (None, Some(_)) => Ending::Ended,
        (Some(a), Some(b)) if a == b && purpose == EndingPurpose::File => Ending::UnlinkSource,
        (None, None) => match purpose {
            EndingPurpose::Superseded {
                set,
                recorded: Some(recorded),
                durable: true,
            } if set == recorded => Ending::Ended,
            EndingPurpose::IncompleteCandidate => Ending::AbsentCandidate,
            _ => Ending::Refuse,
        },
        _ => Ending::Refuse,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Names {
    source: Option<Identity>,
    destination: Option<Identity>,
    purpose: EndingPurpose,
    synchronized: bool,
}

impl Names {
    fn remove_discarded(self) -> Option<Self> {
        let EndingPurpose::Superseded {
            set,
            recorded: Some(recorded),
            durable: true,
        } = self.purpose
        else {
            return None;
        };
        if set != recorded || self.source.is_some() || self.destination.is_none() || !self.synchronized {
            return None;
        }
        Some(Self {
            destination: None,
            ..self
        })
    }

    fn finish(self) -> Option<Self> {
        if let EndingPurpose::Superseded { set, recorded, durable } = self.purpose
            && (recorded != Some(set) || !durable)
        {
            return None;
        }
        let mut next = self;
        match ending(self.source, self.destination, self.purpose) {
            Ending::Refuse => return None,
            Ending::Pending => {
                next.destination = self.source;
                next.source = None;
            }
            Ending::UnlinkSource => next.source = None,
            Ending::Ended | Ending::AbsentCandidate => return Some(self),
        }
        next.synchronized = true;
        Some(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Invocation {
    expected: u8,
    observed: u8,
    ended: bool,
    success: bool,
    status: u8,
    streams_ended: bool,
    lengths: [usize; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Measure {
    premise: [bool; 5],
    calibrated: (u8, u8),
    current: (u8, u8),
    expected: [usize; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Receipt {
    invocations: [Option<Invocation>; 2],
    measures: [Measure; 2],
}

fn good_receipt() -> Receipt {
    let a = Invocation {
        expected: 1,
        observed: 1,
        ended: true,
        success: true,
        status: 0,
        streams_ended: true,
        lengths: [80, 151],
    };
    let b = Invocation {
        expected: 2,
        observed: 2,
        ..a
    };
    let measure = Measure {
        premise: [true; 5],
        calibrated: (1, 1),
        current: (1, 1),
        expected: [80, 151],
    };
    Receipt {
        invocations: [Some(a), Some(b)],
        measures: [measure; 2],
    }
}

fn accepts(invocations: [Option<Invocation>; 2], measures: [Measure; 2]) -> bool {
    invocations.into_iter().zip(measures).all(|(invocation, measure)| {
        invocation.is_some_and(|i| {
            i.expected == i.observed && i.ended && i.success && i.status == 0 && i.streams_ended && i.lengths == measure.expected
        }) && measure.premise.into_iter().all(|p| p)
            && measure.current == measure.calibrated
    }) && invocations[0]
        .zip(invocations[1])
        .is_some_and(|(a, b)| a.expected != b.expected)
}

fn complete(rotation: bool) -> State {
    let mut state = State::initial(rotation);
    for event in [
        Event::Generate,
        Event::Receive(good_receipt()),
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Marker,
        Event::Sync,
    ] {
        state = state.apply(event).expect("valid publication path");
    }
    state
}

fn activation_walk(mut state: State, rotation: bool) {
    assert_eq!(state.phase, Phase::Complete);
    if rotation {
        assert!(
            state.apply(Event::StageSelection).is_none(),
            "selection requires every target-role equality and drain"
        );
    }
    state.equal = Evidence::Present;
    state.drained = Evidence::Present;
    state = state.apply(Event::StageSelection).unwrap();
    assert!(
        state.apply(Event::Select).is_none(),
        "staged selection must be synchronized before replacement"
    );
    assert_eq!(
        state.apply(Event::Recover),
        Some(state),
        "staged selection acknowledgement loss retains the complete candidate"
    );
    state = state.apply(Event::Sync).unwrap();
    state = state.apply(Event::Select).unwrap();
    assert!(
        state.apply(Event::Consume).is_none(),
        "selection synchronization precedes consumption"
    );
    state = state.apply(Event::Sync).unwrap();
    if rotation {
        assert!(
            state.apply(Event::Consume).is_none(),
            "rotation remains unconsumed before login checks"
        );
    }
    state.checked = Evidence::Present;
    assert!(
        state.apply(Event::Start).is_none(),
        "unconsumed authorization forbids consumer start"
    );
    state = state.apply(Event::Consume).unwrap();
    assert!(
        state.apply(Event::Start).is_none(),
        "authorization ending is synchronized before consumer start"
    );
    assert_eq!(
        state.apply(Event::Recover),
        Some(state),
        "uncertain authorization durability never starts a consumer"
    );
    state = state.apply(Event::Sync).unwrap();
    assert_eq!(
        state.apply(Event::Recover),
        Some(state),
        "lost ending acknowledgement reuses the complete set"
    );
    state = state.apply(Event::Start).unwrap();
    if rotation {
        assert!(
            state.apply(Event::Discard).is_none(),
            "discard waits for confirmed activation"
        );
        state.ready = Evidence::Present;
        assert!(
            state.apply(Event::Discard).is_none(),
            "discard requires its recorded administrator act"
        );
        state = state.apply(Event::RecordDisposal).unwrap();
        assert!(
            state.apply(Event::Discard).is_none(),
            "record is durable before the discarded rename"
        );
        state = state.apply(Event::Sync).unwrap();
        state = state.apply(Event::Discard).unwrap();
        assert!(!state.retained);
    }
    assert!(
        state.apply(Event::Generate).is_none(),
        "ended history never authorizes generation"
    );
}

/// Finite walks reach every staged file and marker boundary, selection and
/// authorization ending; recovery cannot silently regenerate a credential.
/// The role equalities are declared inputs owned by the role model, not server evidence.
/// # Panics
/// Panics if a finite model transition violates its declared preconditions.
/// ´claim:generator:publication-model-retains-complete-set-authority´
/// ´test:integration:publication-walk´
#[test]
fn publication_walk() {
    let events = [
        Event::Generate,
        Event::Receive(good_receipt()),
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Link,
        Event::Sync,
        Event::Marker,
        Event::Sync,
    ];
    let mut states = Vec::new();
    let mut transitions = Vec::new();
    for rotation in [true, false] {
        let mut state = State::initial(rotation);
        states.push(state);
        for event in events {
            let before = state;
            state = state.apply(event).expect("valid finite walk");
            transitions.push((before, event, state));
            states.push(state);
            assert!(state.apply(Event::Generate).is_none(), "restart does not regenerate");
            assert!(
                state.apply(Event::Start).is_none(),
                "publication alone never starts a consumer"
            );
        }
        activation_walk(state, rotation);
    }
    // Deliberately traverse the boundary inputs in neither phase nor creation order.
    let order = [9, 2, 13, 0, 7, 4, 11, 6, 1, 12, 5, 10, 3, 8];
    let mut recovery_inputs = Vec::new();
    for index in order {
        for offset in [14, 0] {
            let mut state = states[index + offset];
            state.equal = Evidence::Present;
            recovery_inputs.push(state);
            let recovered = state.apply(Event::Recover).unwrap();
            transitions.push((state, Event::Recover, recovered));
            assert_eq!(recovered.generations, state.generations, "recovery generates no new material");
            if matches!(state.phase, Phase::Staged | Phase::Linked(_) | Phase::Marker) {
                assert_eq!(recovered.phase, Phase::Empty, "incomplete candidate discarded whole");
            }
        }
    }
    assert_eq!(
        states.len(),
        28,
        "two ordered walks supply twenty-eight unsorted boundary inputs"
    );
    assert!(
        states
            .iter()
            .enumerate()
            .all(|(index, state)| !states[..index].contains(state)),
        "boundary states are distinct"
    );
    assert_eq!(recovery_inputs.len(), 28, "twenty-eight shuffled inputs reach recovery");
    assert!(
        recovery_inputs
            .iter()
            .enumerate()
            .all(|(index, state)| !recovery_inputs[..index].contains(state)),
        "actual recovery inputs are distinct"
    );
    assert_eq!(
        transitions.len(),
        54,
        "twenty-six construction and twenty-eight shuffled recovery transitions"
    );
    assert!(
        transitions
            .iter()
            .enumerate()
            .all(|(index, transition)| !transitions[..index].contains(transition)),
        "walk transitions are distinct"
    );
}

fn publication_boundaries(rotation: bool) {
    let good = State::initial(rotation);
    for phase in [
        Phase::Empty,
        Phase::Staged,
        Phase::Linked(1),
        Phase::Marker,
        Phase::Complete,
        Phase::SelectionStaged,
        Phase::SelectionReady,
        Phase::Selected,
        Phase::Active,
        Phase::Discarded,
    ] {
        assert!(
            State { phase, ..good }.apply(Event::Receive(good_receipt())).is_none(),
            "receipt requires generating phase"
        );
    }
    let linked = State {
        phase: Phase::Linked(4),
        synced: Evidence::Present,
        ..good
    };
    assert!(linked.apply(Event::Link).is_none(), "fifth publication link refuses");
    for count in [1, 2, 3] {
        assert!(
            State {
                phase: Phase::Linked(count),
                ..linked
            }
            .apply(Event::Marker)
            .is_none(),
            "marker requires all four links"
        );
    }
}

fn activation_boundaries(rotation: bool) {
    let ready = State {
        equal: Evidence::Present,
        drained: Evidence::Present,
        checked: Evidence::Present,
        phase: Phase::SelectionReady,
        ..complete(rotation)
    };
    assert!(ready.apply(Event::Select).is_some(), "complete selection prerequisites admit");
    assert!(
        State {
            phase: Phase::Complete,
            ..ready
        }
        .apply(Event::Select)
        .is_none(),
        "selection requires ready phase"
    );
    let selected = State {
        phase: Phase::Selected,
        ..ready
    };
    assert!(
        selected.apply(Event::Consume).is_some(),
        "complete consumption prerequisites admit"
    );
    assert!(ready.apply(Event::Consume).is_none(), "consumption requires selected phase");
    if rotation {
        for (state, event, message) in [
            (
                State {
                    equal: Evidence::Missing,
                    ..ready
                },
                Event::Select,
                "selection rechecks rotation equality",
            ),
            (
                State {
                    drained: Evidence::Missing,
                    ..ready
                },
                Event::Select,
                "selection rechecks rotation drain",
            ),
            (
                State {
                    equal: Evidence::Missing,
                    ..selected
                },
                Event::Consume,
                "consumption rechecks rotation equality",
            ),
            (
                State {
                    checked: Evidence::Missing,
                    ..selected
                },
                Event::Consume,
                "consumption requires rotation login check",
            ),
        ] {
            assert!(state.apply(event).is_none(), "{message}");
        }
    }
    start_boundaries(selected);
}

fn start_boundaries(selected: State) {
    let consumed = State {
        authorization: Authorization::Consumed,
        ..selected
    };
    assert!(consumed.apply(Event::Start).is_some(), "complete start prerequisites admit");
    for (state, message) in [
        (
            State {
                phase: Phase::Complete,
                ..consumed
            },
            "start requires selected phase",
        ),
        (
            State {
                equal: Evidence::Missing,
                ..consumed
            },
            "start requires role equality",
        ),
        (
            State {
                checked: Evidence::Missing,
                ..consumed
            },
            "start requires login check",
        ),
        (
            State {
                synced: Evidence::Missing,
                ..consumed
            },
            "start requires synchronized ending",
        ),
    ] {
        assert!(state.apply(Event::Start).is_none(), "{message}");
    }
}

fn recovery_boundaries(rotation: bool) {
    let state = State {
        equal: Evidence::Present,
        ..State::initial(rotation).apply(Event::Generate).unwrap()
    };
    let recovered = state.apply(Event::Recover).unwrap();
    assert_eq!(recovered.phase, Phase::Empty, "generating candidate is discarded by recovery");
    let other = if rotation {
        Authorization::Initial
    } else {
        Authorization::Rotation
    };
    assert!(
        State {
            authorization: other,
            ..state
        }
        .apply(Event::Recover)
        .is_none(),
        "recovery refuses the other authorization class"
    );
    for authorized in [
        References {
            instance: 3,
            ..state.expected
        },
        References {
            creation: 3,
            ..state.expected
        },
        References {
            predecessor: Some(3),
            ..state.expected
        },
    ] {
        assert!(
            State { authorized, ..state }.apply(Event::Recover).is_none(),
            "recovery requires matching authorization references"
        );
    }
    if rotation {
        for (invalid, message) in [
            (
                State {
                    equal: Evidence::Missing,
                    ..state
                },
                "rotation recovery requires old role equality",
            ),
            (
                State {
                    predecessor: Evidence::Missing,
                    ..state
                },
                "rotation recovery requires old complete set",
            ),
            (
                State {
                    selected_predecessor: Evidence::Missing,
                    ..state
                },
                "rotation recovery requires old selection",
            ),
        ] {
            assert!(invalid.apply(Event::Recover).is_none(), "{message}");
        }
        assert_eq!(
            recovered.authorization,
            Authorization::Abandoned,
            "rotation recovery abandons authorization"
        );
        assert!(
            recovered.apply(Event::Generate).is_none(),
            "abandoned recovery cannot generate again"
        );
    }
}

fn generation_prerequisites(rotation: bool) {
    let good = State::initial(rotation);
    for authorization in [
        Authorization::Abandoned,
        Authorization::Missing,
        Authorization::Consumed,
        if rotation {
            Authorization::Initial
        } else {
            Authorization::Rotation
        },
    ] {
        assert!(
            State { authorization, ..good }.apply(Event::Generate).is_none(),
            "authorization classes cannot substitute or reopen"
        );
    }
    assert!(
        State {
            admissible: Evidence::Missing,
            ..good
        }
        .apply(Event::Generate)
        .is_none(),
        "inadmissible store refuses"
    );
    assert!(
        State {
            predecessor: Evidence::from_flag(!rotation),
            ..good
        }
        .apply(Event::Generate)
        .is_none(),
        "store and predecessor match the operation"
    );
    assert!(
        State {
            selected_predecessor: Evidence::from_flag(!rotation),
            ..good
        }
        .apply(Event::Generate)
        .is_none(),
        "authorization names the selected predecessor"
    );
    assert!(
        State {
            store_empty: rotation,
            ..good
        }
        .apply(Event::Generate)
        .is_none(),
        "store emptiness matches initialization or rotation"
    );
    assert!(
        State { retained: true, ..good }.apply(Event::Generate).is_none(),
        "retained superseded set refuses another rotation"
    );
    for authorized in [
        References {
            instance: 3,
            ..good.expected
        },
        References {
            creation: 3,
            ..good.expected
        },
        References {
            predecessor: Some(3),
            ..good.expected
        },
    ] {
        assert!(
            State { authorized, ..good }.apply(Event::Generate).is_none(),
            "authorization binds instance creation and predecessor"
        );
    }
}

fn selection_prerequisites(rotation: bool) {
    let state = complete(rotation);
    assert!(
        State {
            phase: Phase::Staged,
            authorization: Authorization::Consumed,
            ..state
        }
        .apply(Event::Recover)
        .is_none(),
        "incomplete candidate cannot consume ended authorization history"
    );
    for marker in [
        None,
        Some(References {
            instance: 3,
            ..state.expected
        }),
        Some(References {
            creation: 3,
            ..state.expected
        }),
        Some(References {
            predecessor: Some(3),
            ..state.expected
        }),
    ] {
        assert!(
            State {
                marker,
                equal: Evidence::Present,
                drained: Evidence::Present,
                ..state
            }
            .apply(Event::StageSelection)
            .is_none(),
            "selection requires the matching complete-set marker"
        );
    }
    assert!(
        State {
            phase: Phase::Linked(4),
            equal: Evidence::Present,
            drained: Evidence::Present,
            ..state
        }
        .apply(Event::StageSelection)
        .is_none(),
        "selection requires a completed publication"
    );
    assert!(
        State {
            phase: Phase::Staged,
            synced: Evidence::Missing,
            ..state
        }
        .apply(Event::Link)
        .is_none(),
        "unsynchronized publication refuses"
    );
    assert!(
        State {
            phase: Phase::Linked(4),
            synced: Evidence::Missing,
            ..state
        }
        .apply(Event::Marker)
        .is_none(),
        "marker follows directory synchronization"
    );
    assert!(state.apply(Event::Link).is_none(), "complete files cannot be replaced");
    if rotation {
        assert!(
            State {
                equal: Evidence::Missing,
                drained: Evidence::Present,
                ..state
            }
            .apply(Event::StageSelection)
            .is_none(),
            "selection requires every target-role equality"
        );
        assert!(
            State {
                equal: Evidence::Present,
                drained: Evidence::Missing,
                ..state
            }
            .apply(Event::StageSelection)
            .is_none(),
            "selection requires disabled logins and drained sessions"
        );
    }
}

/// Injected states refuse invalid generation, receipt, link, marker, selection,
/// consumption, start and recovery prerequisites; rotation recovery abandons
/// its authorization and refuses generation under it.
/// # Panics
/// Panics if the model accepts a refused authorization or publication boundary.
/// ´claim:generator:publication-model-refuses-invalid-prerequisites´
/// ´test:integration:publication-prerequisites´
#[test]
fn publication_prerequisites() {
    for rotation in [true, false] {
        generation_prerequisites(rotation);
        selection_prerequisites(rotation);
        publication_boundaries(rotation);
        activation_boundaries(rotation);
        recovery_boundaries(rotation);
    }
}

fn discarded_endings(a: Identity) {
    let authorized = Names {
        source: None,
        destination: None,
        purpose: EndingPurpose::Superseded {
            set: 7,
            recorded: Some(7),
            durable: true,
        },
        synchronized: true,
    };
    let retained = Names {
        source: Some(a),
        synchronized: false,
        ..authorized
    };
    assert!(
        retained.remove_discarded().is_none(),
        "removal follows the discarded rename and synchronization"
    );
    let renamed = retained.finish().unwrap();
    assert!(
        Names {
            synchronized: false,
            ..renamed
        }
        .remove_discarded()
        .is_none(),
        "discarded rename is synchronized before removal"
    );
    let removed = renamed.remove_discarded().unwrap();
    assert_eq!(removed, authorized, "removal reaches the authorized absent state");
    assert_eq!(
        removed.finish(),
        Some(removed),
        "lost removal acknowledgement recognizes the recorded act"
    );
    assert_eq!(
        authorized.finish(),
        Some(authorized),
        "authorized absent discarded set acknowledges without changes"
    );
    for purpose in [
        EndingPurpose::Superseded {
            set: 7,
            recorded: None,
            durable: true,
        },
        EndingPurpose::Superseded {
            set: 7,
            recorded: Some(8),
            durable: true,
        },
        EndingPurpose::Superseded {
            set: 7,
            recorded: Some(7),
            durable: false,
        },
    ] {
        assert!(
            Names { purpose, ..authorized }.finish().is_none(),
            "absent superseded set requires its exact durable recorded act"
        );
        assert!(
            Names { purpose, ..retained }.finish().is_none(),
            "rename requires its exact durable recorded act"
        );
        assert!(
            Names { purpose, ..renamed }.remove_discarded().is_none(),
            "removal requires its exact durable recorded act"
        );
    }
    let candidate = Names {
        purpose: EndingPurpose::IncompleteCandidate,
        synchronized: false,
        ..authorized
    };
    assert_eq!(
        ending(None, None, candidate.purpose),
        Ending::AbsentCandidate,
        "absent incomplete candidate supplies no authority"
    );
    assert_eq!(
        candidate.finish(),
        Some(candidate),
        "absent incomplete candidate needs no disposal proof"
    );
    assert!(
        State {
            authorization: Authorization::Missing,
            ..State::initial(false)
        }
        .apply(Event::Generate)
        .is_none(),
        "absent candidate still requires initial authorization"
    );
}

/// File-ending identity is device plus inode; directory endings are atomic
/// no-replace renames and cannot have a link-then-unlink intermediate state.
/// # Panics
/// Panics if a collision is accepted or an interrupted same-file ending is lost.
/// ´claim:generator:publication-endings-distinguish-identity-from-collision´
/// ´test:integration:publication-endings´
#[test]
fn publication_endings() {
    let a = Identity { device: 1, inode: 2 };
    let b = Identity { device: 2, inode: 2 };
    let c = Identity { device: 1, inode: 3 };
    for purpose in [
        EndingPurpose::Superseded {
            set: 1,
            recorded: Some(1),
            durable: true,
        },
        EndingPurpose::File,
    ] {
        for (source, destination, expected) in [
            (Some(a), Some(b), Ending::Refuse),
            (None, Some(a), Ending::Ended),
            (
                Some(a),
                Some(a),
                if purpose == EndingPurpose::File {
                    Ending::UnlinkSource
                } else {
                    Ending::Refuse
                },
            ),
            (Some(a), None, Ending::Pending),
            (Some(a), Some(c), Ending::Refuse),
            (
                None,
                None,
                if purpose == EndingPurpose::File {
                    Ending::Refuse
                } else {
                    Ending::Ended
                },
            ),
        ] {
            assert_eq!(
                ending(source, destination, purpose),
                expected,
                "no-replace ending reads both names and file identity"
            );
            let names = Names {
                source,
                destination,
                purpose,
                synchronized: expected == Ending::Ended,
            };
            if expected == Ending::Refuse {
                assert!(names.finish().is_none(), "collision preserves both names without replacement");
                assert_eq!(
                    names,
                    Names {
                        source,
                        destination,
                        purpose,
                        synchronized: false
                    }
                );
            } else {
                let finished = names.finish().unwrap();
                assert!(
                    finished.source.is_none() && finished.destination == destination.or(source),
                    "ending retains the same object or its authorized absence"
                );
                assert!(finished.synchronized, "ending requires directory synchronization");
                assert_eq!(finished.finish(), Some(finished), "lost ending acknowledgement is idempotent");
            }
        }
    }
    discarded_endings(a);
}

/// Publication owns its invocation pairing and sealed-length comparison;
/// no plaintext reader, actual sealer or installed calibration law is modelled.
/// # Panics
/// Panics if failed completion, missing framing or an invalid measure authorizes a link.
/// ´claim:generator:publication-checks-own-completion-and-measure´
/// ´test:integration:publication-completion´
#[test]
fn publication_completion() {
    let a = Invocation {
        expected: 1,
        observed: 1,
        ended: true,
        success: true,
        status: 0,
        streams_ended: true,
        lengths: [80, 151],
    };
    let b = Invocation {
        expected: 2,
        observed: 2,
        ..a
    };
    let m = Measure {
        premise: [true; 5],
        calibrated: (1, 1),
        current: (1, 1),
        expected: [80, 151],
    };
    let good = [Some(a), Some(b)];
    let generating = State::initial(false).apply(Event::Generate).unwrap();
    assert!(accepts(good, [m; 2]));
    for index in [1, 0] {
        let original = good[index].unwrap();
        for changed in [
            None,
            Some(Invocation { observed: 3, ..original }),
            Some(Invocation {
                ended: false,
                ..original
            }),
            Some(Invocation {
                success: false,
                ..original
            }),
            Some(Invocation { status: 1, ..original }),
            Some(Invocation {
                streams_ended: false,
                ..original
            }),
            Some(Invocation {
                lengths: [79, 151],
                ..original
            }),
            Some(Invocation {
                lengths: [80, 152],
                ..original
            }),
        ] {
            let mut invocations = good;
            invocations[index] = changed;
            assert!(
                !accepts(invocations, [m; 2]),
                "publication refuses each failed incomplete or unmatched invocation"
            );
            assert!(
                generating
                    .apply(Event::Receive(Receipt {
                        invocations,
                        measures: [m; 2]
                    }))
                    .is_none(),
                "invalid invocation cannot enter staged publication"
            );
        }
        for member in [3, 0, 4, 1, 2] {
            let mut measures = [m; 2];
            measures[index].premise[member] = false;
            assert!(!accepts(good, measures), "publication requires every sealed-measure premise");
            assert!(
                generating
                    .apply(Event::Receive(Receipt {
                        invocations: good,
                        measures
                    }))
                    .is_none(),
                "invalid measure cannot enter staged publication"
            );
        }
        for current in [(2, 1), (1, 2)] {
            let mut measures = [m; 2];
            measures[index].current = current;
            assert!(
                !accepts(good, measures),
                "changed measure or format invalidates publication calibration"
            );
        }
    }
    assert!(!accepts([Some(a); 2], [m; 2]), "roles require distinct invocation pairings");
}
