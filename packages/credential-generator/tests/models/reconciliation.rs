#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proof {
    Missing,
    Present,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Forward,
    Abandon,
    Rollback,
}

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
    Authorized,
    Stopped,
    Drained,
    Disabled,
    Changing,
    Equal,
    Staged,
    StageSynced,
    Selected,
    SelectionSynced,
    Enabled,
    Checked,
    Ending,
    Ended,
    Started,
    Active,
    DisposalWritten,
    DisposalRenamed,
    Disposed,
}

const PHASES: [Phase; 19] = [
    Phase::Authorized,
    Phase::Stopped,
    Phase::Drained,
    Phase::Disabled,
    Phase::Changing,
    Phase::Equal,
    Phase::Staged,
    Phase::StageSynced,
    Phase::Selected,
    Phase::SelectionSynced,
    Phase::Enabled,
    Phase::Checked,
    Phase::Ending,
    Phase::Ended,
    Phase::Started,
    Phase::Active,
    Phase::DisposalWritten,
    Phase::DisposalRenamed,
    Phase::Disposed,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reference {
    instance: u8,
    creation: u8,
    predecessor: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Marker {
    reference: Reference,
    invocations: [u8; 2],
    measures: [u16; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Set {
    complete: Proof,
    marker: Marker,
    expected: Marker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rollback {
    reference: Reference,
    target: u8,
    direction: Direction,
    ended: Proof,
    ending: Ending,
    durable: Proof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u8,
    inode: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ending {
    source: Option<Identity>,
    destination: Option<Identity>,
    supported: Proof,
}

impl Ending {
    fn finish(self) -> Result<Self, &'static str> {
        require("ending semantics", self.supported == Proof::Present)?;
        require("ending material", self.source.is_some() || self.destination.is_some())?;
        require(
            "ending collision",
            self.source.zip(self.destination).is_none_or(|(a, b)| a == b),
        )?;
        Ok(Self {
            source: None,
            destination: self.destination.or(self.source),
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    phase: Phase,
    direction: Direction,
    authorization: Authorization,
    authorized: Reference,
    old: Set,
    new: Set,
    selected: u8,
    old_equal: [Proof; 2],
    new_equal: [Proof; 2],
    known: [Proof; 2],
    stopped: Proof,
    drained: Proof,
    disabled: Proof,
    enabled: Proof,
    checked: Proof,
    durable: Proof,
    ending_durable: Proof,
    disposal_durable: Proof,
    schema: Proof,
    grants: Proof,
    ready: Proof,
    retained: Proof,
    store: Proof,
    rollback: Option<Rollback>,
    disposal: Option<u8>,
    ending: Ending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Stop,
    Drain,
    Disable,
    Apply(Role),
    Read(Role, Proof, Proof),
    Confirm,
    Stage,
    SyncStage,
    Select,
    SyncSelection,
    Enable,
    Check,
    End,
    SyncEnd,
    Start,
    Ready,
    AuthorizeRollback,
    RecordDisposal,
    SyncDisposal,
    RenameDisposal,
    RemoveDisposal,
    Rotate(Set),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Instance,
    Store,
}

impl Role {
    fn index(self) -> usize {
        match self {
            Self::Instance => 0,
            Self::Store => 1,
        }
    }
}

type Outcome = Result<State, &'static str>;

fn require(name: &'static str, holds: bool) -> Result<(), &'static str> {
    if holds { Ok(()) } else { Err(name) }
}

impl State {
    fn record_ending(self) -> Ending {
        if self.direction == Direction::Rollback {
            self.rollback.map_or(self.ending, |r| r.ending)
        } else {
            self.ending
        }
    }

    fn record_durable(self) -> Proof {
        if self.direction == Direction::Rollback {
            self.rollback.map_or(self.ending_durable, |r| r.durable)
        } else {
            self.ending_durable
        }
    }

    fn set_record_ending(&mut self, ending: Ending, durable: Proof) {
        if self.direction == Direction::Rollback {
            if let Some(record) = &mut self.rollback {
                record.ending = ending;
                record.durable = durable;
            }
        } else {
            self.ending = ending;
            self.ending_durable = durable;
        }
    }

    fn target(self) -> Set {
        match self.direction {
            Direction::Forward => self.new,
            Direction::Abandon | Direction::Rollback => self.old,
        }
    }

    fn equal(self) -> [Proof; 2] {
        match self.direction {
            Direction::Forward => self.new_equal,
            Direction::Abandon | Direction::Rollback => self.old_equal,
        }
    }

    fn marker(self) -> Result<(), &'static str> {
        let set = self.target();
        require("complete target", set.complete == Proof::Present)?;
        require("marker reference", set.marker.reference == set.expected.reference)?;
        require(
            "marker invocation zero",
            set.marker.invocations[0] == set.expected.invocations[0],
        )?;
        require(
            "marker invocation one",
            set.marker.invocations[1] == set.expected.invocations[1],
        )?;
        require("marker measure zero", set.marker.measures[0] == set.expected.measures[0])?;
        require("marker measure one", set.marker.measures[1] == set.expected.measures[1])?;
        require("marker measure two", set.marker.measures[2] == set.expected.measures[2])?;
        require("marker measure three", set.marker.measures[3] == set.expected.measures[3])
    }

    fn authority(self) -> Result<(), &'static str> {
        self.records()?;
        require("authorization reference", self.authorized == self.new.expected.reference)?;
        match self.direction {
            Direction::Forward | Direction::Abandon => {
                require("rotation authorization", self.authorization == Authorization::Rotation)?;
                require("rotation has no rollback", self.rollback.is_none())?;
            }
            Direction::Rollback => {
                require(
                    "rollback keeps consumed history",
                    self.authorization == Authorization::Consumed,
                )?;
                let record = self.rollback.ok_or("rollback record present")?;
                require("rollback reference", record.reference == self.new.expected.reference)?;
                require("rollback target", record.target == self.old.expected.reference.creation)?;
                require("rollback direction", record.direction == Direction::Rollback)?;
                require("rollback unended", record.ended == Proof::Missing)?;
            }
        }
        Ok(())
    }

    fn records(self) -> Result<(), &'static str> {
        require(
            "contradictory disposal and rollback",
            self.rollback
                .is_none_or(|r| r.ended == Proof::Present || self.disposal != Some(r.target)),
        )
    }

    fn reconciled(self) -> Result<(), &'static str> {
        self.marker()?;
        require("known role zero", self.known[0] == Proof::Present)?;
        require("known role one", self.known[1] == Proof::Present)?;
        require("target equality zero", self.equal()[0] == Proof::Present)?;
        require("target equality one", self.equal()[1] == Proof::Present)?;
        require("compatible schema", self.schema == Proof::Present)?;
        require("required grants", self.grants == Proof::Present)
    }

    fn apply(self, event: Event) -> Outcome {
        match event {
            Event::AuthorizeRollback => self.authorize_rollback(),
            Event::Stop | Event::Drain | Event::Disable | Event::Apply(_) | Event::Read(_, _, _) | Event::Confirm => {
                self.roles(event)
            }
            Event::Stage | Event::SyncStage | Event::Select | Event::SyncSelection => self.selection(event),
            Event::Enable | Event::Check | Event::End | Event::SyncEnd | Event::Start | Event::Ready => self.activation(event),
            Event::RecordDisposal | Event::SyncDisposal | Event::RenameDisposal | Event::RemoveDisposal | Event::Rotate(_) => {
                self.custody(event)
            }
        }
    }

    fn roles(self, event: Event) -> Outcome {
        self.authority()?;
        self.marker()?;
        let mut next = self;
        match event {
            Event::Stop => {
                require("stop phase", self.phase == Phase::Authorized)?;
                next.stopped = Proof::Present;
                next.phase = Phase::Stopped;
            }
            Event::Drain => {
                require("drain phase", self.phase == Phase::Stopped)?;
                require("drain stopped", self.stopped == Proof::Present)?;
                next.drained = Proof::Present;
                next.phase = Phase::Drained;
            }
            Event::Disable => {
                require("disable phase", self.phase == Phase::Drained)?;
                require("disable drained", self.drained == Proof::Present)?;
                next.disabled = Proof::Present;
                next.enabled = Proof::Missing;
                next.phase = Phase::Disabled;
            }
            Event::Apply(role) => {
                require("apply phase", matches!(self.phase, Phase::Disabled | Phase::Changing))?;
                require("apply disabled", self.disabled == Proof::Present)?;
                require("apply drained", self.drained == Proof::Present)?;
                next.known[role.index()] = Proof::Missing;
                next.old_equal[role.index()] = Proof::Missing;
                next.new_equal[role.index()] = Proof::Missing;
                next.checked = Proof::Missing;
                next.phase = Phase::Changing;
            }
            Event::Read(role, old, new) => {
                require("read phase", self.phase == Phase::Changing)?;
                next.known[role.index()] = Proof::Present;
                next.old_equal[role.index()] = old;
                next.new_equal[role.index()] = new;
            }
            Event::Confirm => {
                require("confirm phase", matches!(self.phase, Phase::Disabled | Phase::Changing))?;
                self.reconciled()?;
                next.phase = Phase::Equal;
            }
            _ => return Err("role event"),
        }
        Ok(next)
    }

    fn selection(self, event: Event) -> Outcome {
        self.authority()?;
        self.reconciled()?;
        let mut next = self;
        match event {
            Event::Stage => {
                require("stage phase", self.phase == Phase::Equal)?;
                require("stage disabled", self.disabled == Proof::Present)?;
                require("stage drained", self.drained == Proof::Present)?;
                next.phase = Phase::Staged;
                next.durable = Proof::Missing;
            }
            Event::SyncStage => {
                require("stage sync phase", self.phase == Phase::Staged)?;
                next.durable = Proof::Present;
                next.phase = Phase::StageSynced;
            }
            Event::Select => {
                require("select phase", self.phase == Phase::StageSynced)?;
                require("select durable", self.durable == Proof::Present)?;
                require("select disabled", self.disabled == Proof::Present)?;
                require("select drained", self.drained == Proof::Present)?;
                next.selected = self.target().expected.reference.creation;
                next.durable = Proof::Missing;
                next.phase = Phase::Selected;
            }
            Event::SyncSelection => {
                require("selection sync phase", self.phase == Phase::Selected)?;
                next.durable = Proof::Present;
                next.phase = Phase::SelectionSynced;
            }
            _ => return Err("selection event"),
        }
        Ok(next)
    }

    fn activation(self, event: Event) -> Outcome {
        self.reconciled()?;
        require("selected target", self.selected == self.target().expected.reference.creation)?;
        let mut next = self;
        match event {
            Event::Enable => {
                self.authority()?;
                require("enable phase", self.phase == Phase::SelectionSynced)?;
                require("enable durable", self.durable == Proof::Present)?;
                next.enabled = Proof::Present;
                next.disabled = Proof::Missing;
                next.phase = Phase::Enabled;
            }
            Event::Check => {
                self.authority()?;
                require("check phase", self.phase == Phase::Enabled)?;
                require("check enabled", self.enabled == Proof::Present)?;
                next.checked = Proof::Present;
                next.phase = Phase::Checked;
            }
            Event::End => {
                self.authority()?;
                require("end phase", self.phase == Phase::Checked)?;
                require("end checked", self.checked == Proof::Present)?;
                require("end enabled", self.enabled == Proof::Present)?;
                next.set_record_ending(self.record_ending().finish()?, Proof::Missing);
                next.phase = Phase::Ending;
            }
            Event::SyncEnd => {
                self.authority()?;
                require("ending sync phase", self.phase == Phase::Ending)?;
                require("ending source gone", self.record_ending().source.is_none())?;
                require("ending destination present", self.record_ending().destination.is_some())?;
                match self.direction {
                    Direction::Forward => {
                        next.authorization = Authorization::Consumed;
                        next.retained = Proof::Present;
                    }
                    Direction::Abandon => next.authorization = Authorization::Abandoned,
                    Direction::Rollback => {
                        next.rollback = self.rollback.map(|r| Rollback {
                            ended: Proof::Present,
                            ..r
                        });
                        next.retained = Proof::Present;
                    }
                }
                next.set_record_ending(self.record_ending(), Proof::Present);
                next.phase = Phase::Ended;
            }
            Event::Start => {
                require("start phase", self.phase == Phase::Ended)?;
                require("start durable", self.record_durable() == Proof::Present)?;
                require("start checked", self.checked == Proof::Present)?;
                require("start enabled", self.enabled == Proof::Present)?;
                require("start reference", self.authorized == self.new.expected.reference)?;
                require(
                    "start rollback roster",
                    (self.direction == Direction::Rollback) == self.rollback.is_some(),
                )?;
                require(
                    "start rollback reference",
                    self.rollback.is_none_or(|r| r.reference == self.new.expected.reference),
                )?;
                require(
                    "start rollback target",
                    self.rollback.is_none_or(|r| r.target == self.old.expected.reference.creation),
                )?;
                require(
                    "start rollback direction",
                    self.rollback.is_none_or(|r| r.direction == Direction::Rollback),
                )?;
                require(
                    "start authorization",
                    self.authorization
                        == match self.direction {
                            Direction::Abandon => Authorization::Abandoned,
                            _ => Authorization::Consumed,
                        },
                )?;
                require(
                    "start rollback ended",
                    self.rollback.is_none_or(|r| r.ended == Proof::Present),
                )?;
                next.stopped = Proof::Missing;
                next.phase = Phase::Started;
            }
            Event::Ready => {
                require("ready phase", self.phase == Phase::Started)?;
                next.ready = Proof::Present;
                next.phase = Phase::Active;
            }
            _ => return Err("activation event"),
        }
        Ok(next)
    }

    fn authorize_rollback(self) -> Outcome {
        let mut next = self;
        require(
            "standing disposal",
            self.disposal != Some(self.old.expected.reference.creation),
        )?;
        require(
            "rollback admission phase",
            matches!(self.phase, Phase::Ended | Phase::Started | Phase::Active),
        )?;
        require("rollback admission history", self.authorization == Authorization::Consumed)?;
        require("rollback admission retained", self.retained == Proof::Present)?;
        require("rollback admission complete", self.old.complete == Proof::Present)?;
        require("rollback admission schema", self.schema == Proof::Present)?;
        require(
            "scope limit rollback selected",
            self.selected == self.new.expected.reference.creation,
        )?;
        require("scope limit rollback no record", self.rollback.is_none())?;
        next.rollback = Some(Rollback {
            reference: self.new.expected.reference,
            target: self.old.expected.reference.creation,
            direction: Direction::Rollback,
            ended: Proof::Missing,
            ending: pending_ending(6),
            durable: Proof::Missing,
        });
        next.direction = Direction::Rollback;
        next.phase = Phase::Authorized;
        next.ready = Proof::Missing;
        Ok(next)
    }

    fn custody(self, event: Event) -> Outcome {
        let mut next = self;
        match event {
            Event::RecordDisposal => {
                self.reconciled()?;
                require(
                    "disposal selected",
                    self.selected == self.target().expected.reference.creation,
                )?;
                require("disposal phase", self.phase == Phase::Active)?;
                require("disposal readiness", self.ready == Proof::Present)?;
                require("disposal checked", self.checked == Proof::Present)?;
                require("disposal retained", self.retained == Proof::Present)?;
                require(
                    "disposal no pending rollback",
                    self.rollback.is_none_or(|r| r.ended == Proof::Present),
                )?;
                require("disposal ended history", self.authorization == Authorization::Consumed)?;
                next.disposal = Some(if self.selected == self.new.expected.reference.creation {
                    self.old.expected.reference.creation
                } else {
                    self.new.expected.reference.creation
                });
                next.disposal_durable = Proof::Missing;
                next.phase = Phase::DisposalWritten;
            }
            Event::SyncDisposal => {
                require("disposal sync phase", self.phase == Phase::DisposalWritten)?;
                require("disposal sync present", self.disposal.is_some())?;
                next.disposal_durable = Proof::Present;
            }
            Event::RenameDisposal => {
                require("disposal rename phase", self.phase == Phase::DisposalWritten)?;
                require("disposal rename durable", self.disposal_durable == Proof::Present)?;
                require(
                    "disposal set reference",
                    self.disposal
                        == Some(if self.selected == self.new.expected.reference.creation {
                            self.old.expected.reference.creation
                        } else {
                            self.new.expected.reference.creation
                        }),
                )?;
                require("disposal unselected", self.disposal != Some(self.selected))?;
                next.phase = Phase::DisposalRenamed;
            }
            Event::RemoveDisposal => {
                require("disposal remove phase", self.phase == Phase::DisposalRenamed)?;
                next.retained = Proof::Missing;
                next.phase = Phase::Disposed;
            }
            Event::Rotate(candidate) => {
                require("scope limit next rotation phase", self.phase == Phase::Disposed)?;
                require("next rotation retained", self.retained == Proof::Missing)?;
                require("next rotation store", self.store == Proof::Present)?;
                require("scope limit next rotation readiness", self.ready == Proof::Present)?;
                require(
                    "next rotation instance",
                    candidate.expected.reference.instance == self.new.expected.reference.instance,
                )?;
                require(
                    "next rotation predecessor",
                    candidate.expected.reference.predecessor == self.selected,
                )?;
                require(
                    "next rotation fresh",
                    ![self.old.expected.reference.creation, self.new.expected.reference.creation]
                        .contains(&candidate.expected.reference.creation),
                )?;
                require(
                    "next rotation retired reference",
                    self.disposal != Some(candidate.expected.reference.creation),
                )?;
                next.old = self.target();
                next.new = candidate;
                Self {
                    direction: Direction::Forward,
                    ..next
                }
                .marker()?;
                next.authorized = next.new.expected.reference;
                next.authorization = Authorization::Rotation;
                next.ending = pending_ending(candidate.expected.reference.creation);
                next.ending_durable = Proof::Missing;
                next.old_equal = [Proof::Present; 2];
                next.new_equal = [Proof::Missing; 2];
                next.rollback = None;
                next.direction = Direction::Forward;
                next.phase = Phase::Authorized;
                next.checked = Proof::Missing;
                next.ready = Proof::Missing;
            }
            _ => return Err("custody event"),
        }
        Ok(next)
    }

    fn recover(self, direction: Direction) -> Outcome {
        match self.phase {
            Phase::DisposalWritten => {
                self.records()?;
                return if self.disposal_durable == Proof::Missing {
                    self.apply(Event::SyncDisposal)
                } else {
                    self.apply(Event::RenameDisposal)
                };
            }
            Phase::DisposalRenamed => {
                self.records()?;
                return self.apply(Event::RemoveDisposal);
            }
            Phase::Disposed => {
                self.records()?;
                return Ok(self);
            }
            _ => {}
        }
        self.authority()?;
        require(
            "recovery direction",
            (self.direction == Direction::Rollback) == (direction == Direction::Rollback),
        )?;
        let next = Self { direction, ..self };
        next.marker()?;
        require("recovery old complete", self.old.complete == Proof::Present)?;
        require("recovery known zero", self.known[0] == Proof::Present)?;
        require("recovery known one", self.known[1] == Proof::Present)?;
        require(
            "recovery selection",
            [self.old.expected.reference.creation, self.new.expected.reference.creation].contains(&self.selected),
        )?;
        require("recovery schema", self.schema == Proof::Present)?;
        Ok(Self {
            phase: Phase::Authorized,
            stopped: Proof::Missing,
            drained: Proof::Missing,
            disabled: Proof::Missing,
            enabled: Proof::Missing,
            checked: Proof::Missing,
            ready: Proof::Missing,
            ..next
        })
    }
}

fn fixture_set(creation: u8, predecessor: u8) -> Set {
    let marker = Marker {
        reference: Reference {
            instance: 1,
            creation,
            predecessor,
        },
        invocations: [7, 3],
        measures: [80, 160, 80, 160],
    };
    Set {
        complete: Proof::Present,
        marker,
        expected: marker,
    }
}

fn pending_ending(inode: u8) -> Ending {
    Ending {
        source: Some(Identity { device: 2, inode }),
        destination: None,
        supported: Proof::Present,
    }
}

fn initial(direction: Direction) -> State {
    let old = fixture_set(2, 1);
    let new = fixture_set(3, 2);
    State {
        phase: Phase::Authorized,
        direction,
        authorization: Authorization::Rotation,
        authorized: new.expected.reference,
        old,
        new,
        selected: 2,
        old_equal: [Proof::Present; 2],
        new_equal: [Proof::Missing; 2],
        known: [Proof::Present; 2],
        stopped: Proof::Missing,
        drained: Proof::Missing,
        disabled: Proof::Missing,
        enabled: Proof::Present,
        checked: Proof::Missing,
        durable: Proof::Present,
        ending_durable: Proof::Missing,
        disposal_durable: Proof::Missing,
        schema: Proof::Present,
        grants: Proof::Present,
        ready: Proof::Missing,
        retained: Proof::Missing,
        store: Proof::Present,
        rollback: None,
        disposal: None,
        ending: pending_ending(5),
    }
}

#[path = "reconciliation/controls.rs"]
mod controls;
