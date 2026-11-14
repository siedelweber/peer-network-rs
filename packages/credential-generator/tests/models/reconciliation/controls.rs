use super::*;

fn rollback(s: State) -> Rollback {
    Rollback {
        reference: s.new.expected.reference,
        target: s.old.expected.reference.creation,
        direction: Direction::Rollback,
        ended: Proof::Missing,
        ending: s.ending,
        durable: s.ending_durable,
    }
}

fn rollback_state(mut s: State) -> State {
    s.authorization = Authorization::Consumed;
    s.rollback = Some(rollback(s));
    s.direction = Direction::Rollback;
    s
}

fn fixture(event: Event) -> State {
    let mut s = initial(Direction::Forward);
    s.new_equal = [Proof::Present; 2];
    s.stopped = Proof::Present;
    s.drained = Proof::Present;
    s.disabled = Proof::Present;
    s.enabled = Proof::Present;
    s.checked = Proof::Present;
    s.ready = Proof::Present;
    s.selected = s.new.expected.reference.creation;
    s.ending_durable = Proof::Present;
    s.disposal_durable = Proof::Present;
    s.phase = match event {
        Event::Stop => Phase::Authorized,
        Event::Drain => Phase::Stopped,
        Event::Disable => Phase::Drained,
        Event::Apply(_) => Phase::Disabled,
        Event::Read(_, _, _) | Event::Confirm => Phase::Changing,
        Event::Stage => Phase::Equal,
        Event::SyncStage => Phase::Staged,
        Event::Select => Phase::StageSynced,
        Event::SyncSelection => Phase::Selected,
        Event::Enable => Phase::SelectionSynced,
        Event::Check => Phase::Enabled,
        Event::End => Phase::Checked,
        Event::SyncEnd => Phase::Ending,
        Event::Start => Phase::Ended,
        Event::Ready => Phase::Started,
        Event::AuthorizeRollback | Event::RecordDisposal => Phase::Active,
        Event::SyncDisposal | Event::RenameDisposal => Phase::DisposalWritten,
        Event::RemoveDisposal => Phase::DisposalRenamed,
        Event::Rotate(_) => Phase::Disposed,
    };
    if matches!(event, Event::SyncEnd) {
        s.ending.source = None;
        s.ending.destination = Some(Identity { device: 2, inode: 5 });
    }
    if matches!(
        event,
        Event::Start
            | Event::Ready
            | Event::AuthorizeRollback
            | Event::RecordDisposal
            | Event::RenameDisposal
            | Event::RemoveDisposal
            | Event::Rotate(_)
    ) {
        s.authorization = Authorization::Consumed;
        s.retained = Proof::Present;
    }
    if matches!(
        event,
        Event::SyncDisposal | Event::RenameDisposal | Event::RemoveDisposal | Event::Rotate(_)
    ) {
        s.disposal = Some(s.old.expected.reference.creation);
    }
    if matches!(event, Event::Rotate(_)) {
        s.retained = Proof::Missing;
    }
    s
}

struct Case {
    name: &'static str,
    event: Event,
    good: State,
    change: fn(&mut State),
}

fn cases_0() -> Vec<Case> {
    vec![
        Case {
            name: "complete target",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.complete = Proof::Missing;
            },
        },
        Case {
            name: "marker reference",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.reference.creation = 9;
            },
        },
        Case {
            name: "authorization reference",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.authorized.creation = 9;
            },
        },
        Case {
            name: "rotation authorization",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.authorization = Authorization::Consumed;
            },
        },
        Case {
            name: "rotation has no rollback",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.rollback = Some(rollback(*s));
            },
        },
        Case {
            name: "marker invocation zero",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.invocations[0] += 1;
            },
        },
    ]
}

fn cases_1() -> Vec<Case> {
    vec![
        Case {
            name: "marker invocation one",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.invocations[1] += 1;
            },
        },
        Case {
            name: "marker measure zero",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.measures[0] += 1;
            },
        },
        Case {
            name: "marker measure one",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.measures[1] += 1;
            },
        },
        Case {
            name: "marker measure two",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.measures[2] += 1;
            },
        },
        Case {
            name: "marker measure three",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.new.marker.measures[3] += 1;
            },
        },
        Case {
            name: "rollback keeps consumed history",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.authorization = Authorization::Rotation;
            },
        },
    ]
}

fn cases_2() -> Vec<Case> {
    vec![
        Case {
            name: "rollback reference",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.rollback.as_mut().unwrap().reference.creation = 9;
            },
        },
        Case {
            name: "rollback target",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.rollback.as_mut().unwrap().target = 9;
            },
        },
        Case {
            name: "rollback direction",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.rollback.as_mut().unwrap().direction = Direction::Forward;
            },
        },
        Case {
            name: "rollback unended",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.rollback.as_mut().unwrap().ended = Proof::Present;
            },
        },
        Case {
            name: "rollback record present",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.rollback = None;
            },
        },
        Case {
            name: "contradictory disposal and rollback",
            event: Event::Stop,
            good: {
                let mut s = fixture(Event::Stop);
                s = rollback_state(s);
                s
            },
            change: |s| {
                s.disposal = Some(s.old.expected.reference.creation);
            },
        },
    ]
}

fn cases_3() -> Vec<Case> {
    vec![
        Case {
            name: "known role zero",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.known[0] = Proof::Missing;
            },
        },
        Case {
            name: "target equality zero",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.new_equal[0] = Proof::Missing;
            },
        },
        Case {
            name: "known role one",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.known[1] = Proof::Missing;
            },
        },
        Case {
            name: "target equality one",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.new_equal[1] = Proof::Missing;
            },
        },
        Case {
            name: "compatible schema",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.schema = Proof::Missing;
            },
        },
        Case {
            name: "required grants",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.grants = Proof::Missing;
            },
        },
    ]
}

fn cases_4() -> Vec<Case> {
    vec![
        Case {
            name: "stop phase",
            event: Event::Stop,
            good: fixture(Event::Stop),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "drain phase",
            event: Event::Drain,
            good: fixture(Event::Drain),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "disable phase",
            event: Event::Disable,
            good: fixture(Event::Disable),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "apply phase",
            event: Event::Apply(Role::Instance),
            good: fixture(Event::Apply(Role::Instance)),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "read phase",
            event: Event::Read(Role::Instance, Proof::Missing, Proof::Present),
            good: fixture(Event::Read(Role::Instance, Proof::Missing, Proof::Present)),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "confirm phase",
            event: Event::Confirm,
            good: fixture(Event::Confirm),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
    ]
}

fn cases_5() -> Vec<Case> {
    vec![
        Case {
            name: "stage phase",
            event: Event::Stage,
            good: fixture(Event::Stage),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "stage sync phase",
            event: Event::SyncStage,
            good: fixture(Event::SyncStage),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "select phase",
            event: Event::Select,
            good: fixture(Event::Select),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "selection sync phase",
            event: Event::SyncSelection,
            good: fixture(Event::SyncSelection),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "enable phase",
            event: Event::Enable,
            good: fixture(Event::Enable),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "check phase",
            event: Event::Check,
            good: fixture(Event::Check),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
    ]
}

fn cases_6() -> Vec<Case> {
    vec![
        Case {
            name: "end phase",
            event: Event::End,
            good: fixture(Event::End),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "ending sync phase",
            event: Event::SyncEnd,
            good: fixture(Event::SyncEnd),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "start phase",
            event: Event::Start,
            good: fixture(Event::Start),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "ready phase",
            event: Event::Ready,
            good: fixture(Event::Ready),
            change: |s| {
                s.phase = Phase::Authorized;
            },
        },
        Case {
            name: "rollback admission phase",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.phase = Phase::Checked;
            },
        },
        Case {
            name: "disposal phase",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
    ]
}

fn cases_7() -> Vec<Case> {
    vec![
        Case {
            name: "disposal rename phase",
            event: Event::RenameDisposal,
            good: fixture(Event::RenameDisposal),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "disposal remove phase",
            event: Event::RemoveDisposal,
            good: fixture(Event::RemoveDisposal),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "scope limit next rotation phase",
            event: Event::Rotate(fixture_set(4, 3)),
            good: fixture(Event::Rotate(fixture_set(4, 3))),
            change: |s| {
                s.phase = Phase::Started;
            },
        },
        Case {
            name: "drain stopped",
            event: Event::Drain,
            good: fixture(Event::Drain),
            change: |s| {
                s.stopped = Proof::Missing;
            },
        },
        Case {
            name: "disable drained",
            event: Event::Disable,
            good: fixture(Event::Disable),
            change: |s| {
                s.drained = Proof::Missing;
            },
        },
        Case {
            name: "apply disabled",
            event: Event::Apply(Role::Instance),
            good: fixture(Event::Apply(Role::Instance)),
            change: |s| {
                s.disabled = Proof::Missing;
            },
        },
    ]
}

fn cases_8() -> Vec<Case> {
    vec![
        Case {
            name: "apply drained",
            event: Event::Apply(Role::Instance),
            good: fixture(Event::Apply(Role::Instance)),
            change: |s| {
                s.drained = Proof::Missing;
            },
        },
        Case {
            name: "stage disabled",
            event: Event::Stage,
            good: fixture(Event::Stage),
            change: |s| {
                s.disabled = Proof::Missing;
            },
        },
        Case {
            name: "stage drained",
            event: Event::Stage,
            good: fixture(Event::Stage),
            change: |s| {
                s.drained = Proof::Missing;
            },
        },
        Case {
            name: "select durable",
            event: Event::Select,
            good: fixture(Event::Select),
            change: |s| {
                s.durable = Proof::Missing;
            },
        },
        Case {
            name: "select disabled",
            event: Event::Select,
            good: fixture(Event::Select),
            change: |s| {
                s.disabled = Proof::Missing;
            },
        },
        Case {
            name: "select drained",
            event: Event::Select,
            good: fixture(Event::Select),
            change: |s| {
                s.drained = Proof::Missing;
            },
        },
    ]
}

fn cases_9() -> Vec<Case> {
    vec![
        Case {
            name: "enable durable",
            event: Event::Enable,
            good: fixture(Event::Enable),
            change: |s| {
                s.durable = Proof::Missing;
            },
        },
        Case {
            name: "check enabled",
            event: Event::Check,
            good: fixture(Event::Check),
            change: |s| {
                s.enabled = Proof::Missing;
            },
        },
        Case {
            name: "end checked",
            event: Event::End,
            good: fixture(Event::End),
            change: |s| {
                s.checked = Proof::Missing;
            },
        },
        Case {
            name: "end enabled",
            event: Event::End,
            good: fixture(Event::End),
            change: |s| {
                s.enabled = Proof::Missing;
            },
        },
        Case {
            name: "start durable",
            event: Event::Start,
            good: fixture(Event::Start),
            change: |s| {
                s.ending_durable = Proof::Missing;
            },
        },
        Case {
            name: "start checked",
            event: Event::Start,
            good: fixture(Event::Start),
            change: |s| {
                s.checked = Proof::Missing;
            },
        },
    ]
}

fn cases_10() -> Vec<Case> {
    vec![
        Case {
            name: "start enabled",
            event: Event::Start,
            good: fixture(Event::Start),
            change: |s| {
                s.enabled = Proof::Missing;
            },
        },
        Case {
            name: "rollback admission retained",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.retained = Proof::Missing;
            },
        },
        Case {
            name: "rollback admission complete",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.old.complete = Proof::Missing;
            },
        },
        Case {
            name: "rollback admission schema",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.schema = Proof::Missing;
            },
        },
        Case {
            name: "disposal readiness",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.ready = Proof::Missing;
            },
        },
        Case {
            name: "disposal checked",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.checked = Proof::Missing;
            },
        },
    ]
}

fn cases_11() -> Vec<Case> {
    vec![
        Case {
            name: "disposal retained",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.retained = Proof::Missing;
            },
        },
        Case {
            name: "disposal rename durable",
            event: Event::RenameDisposal,
            good: fixture(Event::RenameDisposal),
            change: |s| {
                s.disposal_durable = Proof::Missing;
            },
        },
        Case {
            name: "next rotation store",
            event: Event::Rotate(fixture_set(4, 3)),
            good: fixture(Event::Rotate(fixture_set(4, 3))),
            change: |s| {
                s.store = Proof::Missing;
            },
        },
        Case {
            name: "scope limit next rotation readiness",
            event: Event::Rotate(fixture_set(4, 3)),
            good: fixture(Event::Rotate(fixture_set(4, 3))),
            change: |s| {
                s.ready = Proof::Missing;
            },
        },
        Case {
            name: "selected target",
            event: Event::Enable,
            good: fixture(Event::Enable),
            change: |s| {
                s.selected = s.old.expected.reference.creation;
            },
        },
        Case {
            name: "ending source gone",
            event: Event::SyncEnd,
            good: fixture(Event::SyncEnd),
            change: |s| {
                s.ending.source = Some(Identity { device: 2, inode: 5 });
            },
        },
    ]
}

fn cases_12() -> Vec<Case> {
    vec![
        Case {
            name: "ending destination present",
            event: Event::SyncEnd,
            good: fixture(Event::SyncEnd),
            change: |s| {
                s.ending.destination = None;
            },
        },
        Case {
            name: "start authorization",
            event: Event::Start,
            good: fixture(Event::Start),
            change: |s| {
                s.authorization = Authorization::Rotation;
            },
        },
        Case {
            name: "start rollback ended",
            event: Event::Start,
            good: rollback_start(),
            change: |s| {
                s.rollback.as_mut().unwrap().ended = Proof::Missing;
            },
        },
        Case {
            name: "standing disposal",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.disposal = Some(s.old.expected.reference.creation);
            },
        },
        Case {
            name: "rollback admission history",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.authorization = Authorization::Abandoned;
            },
        },
        Case {
            name: "scope limit rollback selected",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.selected = s.old.expected.reference.creation;
            },
        },
    ]
}

fn cases_13() -> Vec<Case> {
    vec![
        Case {
            name: "scope limit rollback no record",
            event: Event::AuthorizeRollback,
            good: fixture(Event::AuthorizeRollback),
            change: |s| {
                s.rollback = Some(rollback(*s));
            },
        },
        Case {
            name: "disposal selected",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.selected = s.old.expected.reference.creation;
            },
        },
        Case {
            name: "disposal no pending rollback",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.rollback = Some(rollback(*s));
            },
        },
        Case {
            name: "disposal ended history",
            event: Event::RecordDisposal,
            good: fixture(Event::RecordDisposal),
            change: |s| {
                s.authorization = Authorization::Rotation;
            },
        },
        Case {
            name: "disposal set reference",
            event: Event::RenameDisposal,
            good: fixture(Event::RenameDisposal),
            change: |s| {
                s.disposal = None;
            },
        },
        Case {
            name: "disposal unselected",
            event: Event::RenameDisposal,
            good: fixture(Event::RenameDisposal),
            change: |s| {
                s.old.expected.reference.creation = s.selected;
                s.disposal = Some(s.selected);
            },
        },
    ]
}

fn cases_14() -> Vec<Case> {
    vec![
        Case {
            name: "next rotation retained",
            event: Event::Rotate(fixture_set(4, 3)),
            good: fixture(Event::Rotate(fixture_set(4, 3))),
            change: |s| {
                s.retained = Proof::Present;
            },
        },
        Case {
            name: "ending semantics",
            event: Event::End,
            good: fixture(Event::End),
            change: |s| {
                s.ending.supported = Proof::Missing;
            },
        },
        Case {
            name: "ending material",
            event: Event::End,
            good: fixture(Event::End),
            change: |s| {
                s.ending.source = None;
            },
        },
        Case {
            name: "ending collision",
            event: Event::End,
            good: fixture(Event::End),
            change: |s| {
                s.ending.destination = Some(Identity { device: 3, inode: 5 });
            },
        },
    ]
}

fn rollback_start() -> State {
    let mut s = rollback_state(fixture(Event::Start));
    s.selected = s.old.expected.reference.creation;
    s.rollback.as_mut().unwrap().ended = Proof::Present;
    s
}

fn additional_cases() -> Vec<Case> {
    vec![
        Case {
            name: "start reference",
            event: Event::Start,
            good: fixture(Event::Start),
            change: |s| {
                s.authorized.creation = 9;
            },
        },
        Case {
            name: "start rollback roster",
            event: Event::Start,
            good: rollback_start(),
            change: |s| {
                s.rollback = None;
            },
        },
        Case {
            name: "start rollback reference",
            event: Event::Start,
            good: rollback_start(),
            change: |s| {
                s.rollback.as_mut().unwrap().reference.creation = 9;
            },
        },
        Case {
            name: "start rollback target",
            event: Event::Start,
            good: rollback_start(),
            change: |s| {
                s.rollback.as_mut().unwrap().target = 9;
            },
        },
        Case {
            name: "start rollback direction",
            event: Event::Start,
            good: rollback_start(),
            change: |s| {
                s.rollback.as_mut().unwrap().direction = Direction::Forward;
            },
        },
        Case {
            name: "disposal set reference",
            event: Event::RenameDisposal,
            good: fixture(Event::RenameDisposal),
            change: |s| {
                s.disposal = Some(9);
            },
        },
    ]
}

fn disposal_sync_cases() -> Vec<Case> {
    vec![
        Case {
            name: "disposal sync phase",
            event: Event::SyncDisposal,
            good: fixture(Event::SyncDisposal),
            change: |s| {
                s.phase = Phase::Active;
            },
        },
        Case {
            name: "disposal sync present",
            event: Event::SyncDisposal,
            good: fixture(Event::SyncDisposal),
            change: |s| {
                s.disposal = None;
            },
        },
    ]
}

fn cases() -> Vec<Case> {
    [
        cases_0(),
        cases_1(),
        cases_2(),
        cases_3(),
        cases_4(),
        cases_5(),
        cases_6(),
        cases_7(),
        cases_8(),
        cases_9(),
        cases_10(),
        cases_11(),
        cases_12(),
        cases_13(),
        cases_14(),
        additional_cases(),
        disposal_sync_cases(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Named clauses have isolated public-state refusals and every non-target phase.
/// The named scope limits exclude further rollback and next rotation without
/// completed disposal and readiness; these are not procedure rules.
///
/// # Panics
/// Panics only if an admitted fixture or a clause refusal differs from its law.
/// ´claim:generator:role-model-pins-each-reconciliation-clause´
/// ´test:integration:role-prerequisites´
#[test]
fn role_prerequisites() {
    reference_bindings();
    reconciliation_call_sites();
    for authorization in [
        Authorization::Missing,
        Authorization::Initial,
        Authorization::Consumed,
        Authorization::Abandoned,
    ] {
        assert_eq!(
            State {
                authorization,
                ..fixture(Event::Stop)
            }
            .apply(Event::Stop),
            Err("rotation authorization"),
            "ended or foreign authorization cannot substitute"
        );
    }
    let cases = cases();
    for case in &cases {
        assert!(case.good.apply(case.event).is_ok(), "positive fixture: {}", case.name);
        let mut changed = case.good;
        (case.change)(&mut changed);
        assert_eq!(changed.apply(case.event), Err(case.name), "clause: {}", case.name);
        if case.name.ends_with(" phase") {
            for phase in PHASES {
                let allowed = match case.event {
                    Event::Apply(_) | Event::Confirm => matches!(phase, Phase::Disabled | Phase::Changing),
                    Event::AuthorizeRollback => matches!(phase, Phase::Ended | Phase::Started | Phase::Active),
                    _ => phase == case.good.phase,
                };
                if !allowed {
                    assert_eq!(
                        State { phase, ..case.good }.apply(case.event),
                        Err(case.name),
                        "phase clause: {}",
                        case.name
                    );
                }
            }
        }
    }
    assert_eq!(cases.len(), 96, "transition refusal fixtures");
    let state = fixture(Event::Rotate(fixture_set(4, 3)));
    for (name, reference) in [
        (
            "next rotation instance",
            Reference {
                instance: 2,
                creation: 4,
                predecessor: 3,
            },
        ),
        (
            "next rotation predecessor",
            Reference {
                instance: 1,
                creation: 4,
                predecessor: 2,
            },
        ),
        (
            "next rotation fresh",
            Reference {
                instance: 1,
                creation: 3,
                predecessor: 3,
            },
        ),
        (
            "next rotation fresh",
            Reference {
                instance: 1,
                creation: 2,
                predecessor: 3,
            },
        ),
    ] {
        let mut candidate = fixture_set(4, 3);
        candidate.expected.reference = reference;
        candidate.marker.reference = reference;
        assert_eq!(state.apply(Event::Rotate(candidate)), Err(name), "clause: {name}");
    }
    let candidate = fixture_set(1, 3);
    assert_eq!(
        State {
            disposal: Some(1),
            ..state
        }
        .apply(Event::Rotate(candidate)),
        Err("next rotation retired reference"),
        "clause: next rotation retired reference"
    );
}

fn advance(state: State, event: Event, states: &mut Vec<State>, transitions: &mut Vec<(State, Event, State)>) -> State {
    let next = state.apply(event).expect("admitted model transition");
    if !states.contains(&state) {
        states.push(state);
    }
    if !states.contains(&next) {
        states.push(next);
    }
    let transition = (state, event, next);
    if !transitions.contains(&transition) {
        transitions.push(transition);
    }
    next
}

fn walk(mut state: State, states: &mut Vec<State>, transitions: &mut Vec<(State, Event, State)>) -> State {
    for event in [Event::Stop, Event::Drain, Event::Disable] {
        state = advance(state, event, states, transitions);
    }
    for role in [Role::Store, Role::Instance] {
        state = advance(state, Event::Apply(role), states, transitions);
        assert_eq!(
            state.known[role.index()],
            Proof::Missing,
            "role write has uncertain completion"
        );
        assert_eq!(
            state.old_equal[role.index()],
            Proof::Missing,
            "write invalidates old equality"
        );
        assert_eq!(
            state.new_equal[role.index()],
            Proof::Missing,
            "write invalidates new equality"
        );
        assert!(state.recover(state.direction).is_err(), "unknown commit freezes recovery");
        let (old, new) = match state.direction {
            Direction::Forward => (Proof::Missing, Proof::Present),
            _ => (Proof::Present, Proof::Missing),
        };
        state = advance(state, Event::Read(role, old, new), states, transitions);
        if role == Role::Store && state.direction == Direction::Forward {
            assert_eq!(
                state.new_equal,
                [Proof::Missing, Proof::Present],
                "mixed roles remain distinct"
            );
            assert!(state.apply(Event::Confirm).is_err(), "mixed roles forbid selection");
        }
    }
    for event in [
        Event::Confirm,
        Event::Stage,
        Event::SyncStage,
        Event::Select,
        Event::SyncSelection,
        Event::Enable,
        Event::Check,
        Event::End,
        Event::SyncEnd,
    ] {
        if event == Event::End && state.direction == Direction::Rollback {
            assert_eq!(
                state.record_ending(),
                pending_ending(6),
                "rollback ending starts at its own source name"
            );
            assert_eq!(
                state.record_durable(),
                Proof::Missing,
                "rollback ending synchronization starts pending"
            );
        }
        state = advance(state, event, states, transitions);
        if event == Event::End {
            assert!(state.record_ending().source.is_none(), "ending removes only the source name");
            assert!(state.record_ending().destination.is_some(), "ending retains its history");
            assert_eq!(
                state.record_durable(),
                Proof::Missing,
                "ending requires a separate synchronization"
            );
        }
        if event == Event::SyncEnd {
            assert_eq!(
                state.record_durable(),
                Proof::Present,
                "ending synchronization precedes start"
            );
        }
        assert!(
            state.phase == Phase::Ended || state.apply(Event::Start).is_err(),
            "pending reconciliation forbids start"
        );
    }
    state
}

/// Finite paths permute role order and recovery stride, retaining separate equalities
/// through uncertain writes, selection, both rotation endings and rollback before
/// readiness with its own pending ending; next rotation reaches admission only.
///
/// # Panics
/// Panics only if a finite admitted transition or its stated postcondition fails.
/// ´claim:generator:role-model-walks-directional-reconciliation´
/// ´test:integration:role-walk´
#[test]
fn role_walk() {
    let mut states = Vec::new();
    let mut transitions = Vec::new();
    for direction in [Direction::Abandon, Direction::Forward] {
        let ended = walk(initial(direction), &mut states, &mut transitions);
        let started = advance(ended, Event::Start, &mut states, &mut transitions);
        let completed = advance(started, Event::Ready, &mut states, &mut transitions);
        assert_eq!(
            completed.authorization,
            if direction == Direction::Forward {
                Authorization::Consumed
            } else {
                Authorization::Abandoned
            },
            "rotation ending preserves its direction"
        );
        assert_eq!(
            completed.selected,
            if direction == Direction::Forward { 3 } else { 2 },
            "direction selects the corresponding complete set"
        );
        assert_eq!(
            completed.new,
            initial(direction).new,
            "abandonment never regenerates or mixes a complete candidate"
        );
        if direction == Direction::Forward {
            for failed_activation in [ended, started] {
                assert!(
                    failed_activation.apply(Event::AuthorizeRollback).is_ok(),
                    "rollback admitted before reported readiness"
                );
                let admitted = advance(failed_activation, Event::AuthorizeRollback, &mut states, &mut transitions);
                assert_eq!(
                    admitted.phase,
                    Phase::Authorized,
                    "rollback admitted before reported readiness"
                );
                let restored = walk(admitted, &mut states, &mut transitions);
                assert_eq!(restored.selected, 2, "failed activation rollback restores old selection");
            }
            let authorized = advance(completed, Event::AuthorizeRollback, &mut states, &mut transitions);
            assert_eq!(authorized.phase, Phase::Authorized, "rollback record precedes first stop");
            assert!(
                authorized.apply(Event::Start).is_err(),
                "unended rollback forbids start before first stop"
            );
            let rolled_end = walk(authorized, &mut states, &mut transitions);
            let rolled_start = advance(rolled_end, Event::Start, &mut states, &mut transitions);
            let rolled = advance(rolled_start, Event::Ready, &mut states, &mut transitions);
            assert_eq!(rolled.ending, completed.ending, "rollback preserves rotation ending history");
            assert_eq!(
                rolled.ending_durable, completed.ending_durable,
                "rollback preserves rotation synchronization history"
            );
            assert_eq!(rolled.selected, 2, "rollback restores the recorded target");
            assert_eq!(
                rolled.authorization,
                Authorization::Consumed,
                "rollback never reopens rotation history"
            );
            assert_eq!(
                rolled.rollback.unwrap().ended,
                Proof::Present,
                "rollback record ends separately"
            );
            for active in [completed, rolled] {
                walk_disposal(active, &mut states, &mut transitions);
            }
        }
    }
    assert_eq!(states.len(), 67, "distinct walked states");
    assert_eq!(transitions.len(), 68, "distinct walked transitions");
    interruption_checks(&states);
}

fn walk_disposal(active: State, states: &mut Vec<State>, transitions: &mut Vec<(State, Event, State)>) {
    let written = advance(active, Event::RecordDisposal, states, transitions);
    let synchronized = advance(written, Event::SyncDisposal, states, transitions);
    assert_eq!(
        written.recover(written.direction),
        Ok(synchronized),
        "present disposal synchronizes before further recovery"
    );
    assert_eq!(
        synchronized.disposal_durable,
        Proof::Present,
        "disposal synchronization is recorded"
    );
    let renamed = advance(synchronized, Event::RenameDisposal, states, transitions);
    let disposed = advance(renamed, Event::RemoveDisposal, states, transitions);
    assert_eq!(
        synchronized.recover(synchronized.direction),
        Ok(renamed),
        "disposal recovery only advances"
    );
    assert_eq!(renamed.recover(renamed.direction), Ok(disposed), "disposal removal resumes");
    assert_eq!(
        disposed.recover(disposed.direction),
        Ok(disposed),
        "ended disposal acknowledgement is idempotent"
    );
    assert_eq!(
        disposed.retained,
        Proof::Missing,
        "disposal releases the single retained slot"
    );
    let next = advance(
        disposed,
        Event::Rotate(fixture_set(4, disposed.selected)),
        states,
        transitions,
    );
    assert_eq!(
        next.old.expected.reference.creation, disposed.selected,
        "next rotation uses the selected predecessor"
    );
    assert_eq!(
        next.authorization,
        Authorization::Rotation,
        "new rotation has fresh authority"
    );
    assert_eq!(next.disposal, disposed.disposal, "disposal history is retained");
    assert_eq!(
        next.ending,
        pending_ending(4),
        "next rotation ending starts at its own source name"
    );
    assert_eq!(
        next.ending_durable,
        Proof::Missing,
        "next rotation ending synchronization starts pending"
    );
}

/// Recovery refuses missing, ended or contradictory direction records and unknown
/// roles; rollback admission is refused after a present disposal act, which recovery
/// synchronizes before further steps and never cancels.
///
/// # Panics
/// Panics only if a recorded direction or injected refusal differs from the model law.
/// ´claim:generator:role-model-refuses-contradictory-recovery´
/// ´test:integration:role-recovery´
#[test]
fn role_recovery() {
    let good = initial(Direction::Forward);
    assert!(good.recover(Direction::Forward).is_ok(), "forward recovery admitted");
    for (name, changed) in [
        (
            "recovery old complete",
            State {
                old: Set {
                    complete: Proof::Missing,
                    ..good.old
                },
                ..good
            },
        ),
        (
            "recovery known zero",
            State {
                known: [Proof::Missing, Proof::Present],
                ..good
            },
        ),
        (
            "recovery known one",
            State {
                known: [Proof::Present, Proof::Missing],
                ..good
            },
        ),
        ("recovery selection", State { selected: 9, ..good }),
        (
            "recovery schema",
            State {
                schema: Proof::Missing,
                ..good
            },
        ),
    ] {
        assert_eq!(changed.recover(Direction::Forward), Err(name), "clause: {name}");
    }
    let rollback = rollback_state(good);
    assert_eq!(
        rollback.target(),
        rollback.old,
        "rollback uses its recorded target companions"
    );
    assert_eq!(
        rollback.recover(Direction::Forward),
        Err("recovery direction"),
        "clause: recovery direction"
    );
    assert_eq!(
        State {
            disposal: Some(2),
            ..rollback
        }
        .recover(Direction::Rollback),
        Err("contradictory disposal and rollback"),
        "injected contradictory records freeze"
    );
    let active = fixture(Event::AuthorizeRollback);
    assert!(
        active.apply(Event::AuthorizeRollback).is_ok(),
        "rollback admitted before disposal act"
    );
    for phase in [Phase::Active, Phase::DisposalWritten, Phase::DisposalRenamed, Phase::Disposed] {
        assert_eq!(
            State {
                disposal: Some(2),
                phase,
                ..active
            }
            .apply(Event::AuthorizeRollback),
            Err("standing disposal"),
            "clause: standing disposal"
        );
    }
    for phase in [Phase::DisposalWritten, Phase::DisposalRenamed, Phase::Disposed] {
        let bad = State {
            phase,
            ..rollback_state(fixture(Event::RenameDisposal))
        };
        assert_eq!(
            bad.recover(Direction::Rollback),
            Err("contradictory disposal and rollback"),
            "injected contradictory post-act records freeze"
        );
    }
    assert!(
        State {
            disposal: Some(1),
            ..active
        }
        .apply(Event::AuthorizeRollback)
        .is_ok(),
        "an earlier creation's act is not this set's act"
    );
    ending_equalities();
}

fn reference_bindings() {
    let good = fixture(Event::Stop);
    for reference in [
        Reference {
            instance: 9,
            ..good.authorized
        },
        Reference {
            creation: 9,
            ..good.authorized
        },
        Reference {
            predecessor: 9,
            ..good.authorized
        },
    ] {
        assert_eq!(
            State {
                authorized: reference,
                ..good
            }
            .apply(Event::Stop),
            Err("authorization reference"),
            "authorization binds all reference members"
        );
        let mut bad = good;
        bad.new.marker.reference = reference;
        assert_eq!(
            bad.apply(Event::Stop),
            Err("marker reference"),
            "marker binds all reference members"
        );
        let mut bad = rollback_state(good);
        bad.rollback.as_mut().unwrap().reference = reference;
        assert_eq!(
            bad.apply(Event::Stop),
            Err("rollback reference"),
            "rollback binds all reference members"
        );
    }
    let mut ended = rollback_start();
    ended.disposal = Some(ended.old.expected.reference.creation);
    assert_eq!(ended.records(), Ok(()), "ended rollback is history beside a disposal act");
    let mut live = rollback_state(good);
    live.disposal = Some(1);
    assert_eq!(live.records(), Ok(()), "another creation's act is not contradictory");
    assert_eq!(good.records(), Ok(()), "absent rollback has no contradiction");
}

fn reconciliation_call_sites() {
    for event in [
        Event::Confirm,
        Event::Stage,
        Event::Select,
        Event::End,
        Event::Start,
        Event::RecordDisposal,
    ] {
        for direction in [Direction::Forward, Direction::Abandon, Direction::Rollback] {
            if event == Event::RecordDisposal && direction == Direction::Abandon {
                continue;
            }
            let mut good = fixture(event);
            good.direction = direction;
            if direction != Direction::Forward {
                good.selected = 2;
            }
            if direction == Direction::Rollback {
                good = rollback_state(good);
                if matches!(event, Event::Start | Event::RecordDisposal) {
                    good.rollback.as_mut().unwrap().ended = Proof::Present;
                }
            } else if event == Event::Start && direction == Direction::Abandon {
                good.authorization = Authorization::Abandoned;
            }
            assert!(good.apply(event).is_ok(), "reconciliation call-site positive");
            for role in [Role::Store, Role::Instance] {
                let mut bad = good;
                if direction == Direction::Forward {
                    bad.new_equal[role.index()] = Proof::Missing;
                } else {
                    bad.old_equal[role.index()] = Proof::Missing;
                }
                let name = if role == Role::Instance {
                    "target equality zero"
                } else {
                    "target equality one"
                };
                assert_eq!(bad.apply(event), Err(name), "reconciliation at every call site");
            }
        }
    }
}

/// File endings distinguish source-only, destination-only, identical file identity,
/// different-object collisions and absent material; each authorization has its own
/// ending and synchronization state, with the rollback source pinned by the walk.
///
/// # Panics
/// Panics only if a finite ending reading changes history or admits missing material.
/// ´claim:generator:rollback-endings-preserve-file-history´
/// ´test:integration:role-endings´
#[test]
fn role_endings() {
    let id = Identity { device: 2, inode: 5 };
    let pending = Ending {
        source: Some(id),
        destination: None,
        supported: Proof::Present,
    };
    let ended = Ending {
        source: None,
        destination: Some(id),
        ..pending
    };
    assert_eq!(pending.finish(), Ok(ended), "source-only ending keeps destination history");
    assert_eq!(ended.finish(), Ok(ended), "ended acknowledgement is idempotent");
    assert_eq!(
        Ending {
            destination: Some(id),
            ..pending
        }
        .finish(),
        Ok(ended),
        "same-file interrupted ending removes source only"
    );
    for other in [Identity { device: 3, inode: 5 }, Identity { device: 2, inode: 6 }] {
        assert_eq!(
            Ending {
                destination: Some(other),
                ..pending
            }
            .finish(),
            Err("ending collision"),
            "clause: ending collision"
        );
    }
    assert_eq!(
        Ending { source: None, ..pending }.finish(),
        Err("ending material"),
        "clause: ending material"
    );
    assert_eq!(
        Ending {
            supported: Proof::Missing,
            ..pending
        }
        .finish(),
        Err("ending semantics"),
        "clause: ending semantics"
    );
}

fn interruption_checks(states: &[State]) {
    let count = states.len();
    for offset in 0..count {
        let state = states[(offset * 17) % count];
        if matches!(
            state.phase,
            Phase::Authorized
                | Phase::Stopped
                | Phase::Drained
                | Phase::Disabled
                | Phase::Changing
                | Phase::Equal
                | Phase::Staged
                | Phase::StageSynced
                | Phase::Selected
                | Phase::SelectionSynced
                | Phase::Enabled
                | Phase::Checked
        ) {
            if state.known.contains(&Proof::Missing) {
                assert!(state.recover(state.direction).is_err(), "unknown role cannot be inferred");
            } else {
                assert!(
                    state.recover(state.direction).is_ok(),
                    "known interrupted transaction reconciles without regeneration"
                );
            }
        }
    }
}

fn ending_equalities() {
    for direction in [Direction::Forward, Direction::Abandon, Direction::Rollback] {
        let mut s = fixture(Event::End);
        s.direction = direction;
        if direction == Direction::Rollback {
            s = rollback_state(s);
        }
        if direction != Direction::Forward {
            s.selected = 2;
        }
        for role in [Role::Store, Role::Instance] {
            let mut bad = s;
            if direction == Direction::Forward {
                bad.new_equal[role.index()] = Proof::Missing;
            } else {
                bad.old_equal[role.index()] = Proof::Missing;
            }
            assert!(
                bad.apply(Event::End).is_err(),
                "old and new equality cannot substitute at ending"
            );
        }
    }
}
