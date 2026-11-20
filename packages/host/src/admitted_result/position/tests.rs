use super::*;

use crate::admitted_carrier_tests::{base, fixture};
use pn_epoch::publication::disclosures as d;

mod nested;
mod refusals;
mod release;
pub(super) use release::release_site;

fn packages() -> &'static (AdmittedPackage, AdmittedPackage) {
    static PACKAGES: std::sync::OnceLock<(AdmittedPackage, AdmittedPackage)> = std::sync::OnceLock::new();
    PACKAGES.get_or_init(|| {
        let (complete, verifier) = fixture::complete();
        let mut first = complete.disclosures();
        first.frames.truncate(1);
        (d::restore(first, &verifier).unwrap(), complete)
    })
}
fn position<'a>(package: &'a AdmittedPackage, parent: Option<&Position<'a>>) -> Position<'a> {
    Position::from_package(package, parent, RECIPE, usize::MAX, &mut EncodingUsage::default(), |_| Ok(())).unwrap()
}
fn bytes(input: &Input<'_>, parent: Option<&Input<'_>>, residue: Option<&[u8; 32]>) -> Vec<u8> {
    Builder {
        ceiling: usize::MAX,
        usage: &mut EncodingUsage::default(),
        reservation: &mut |_| Ok(()),
    }
    .preimage(input, parent, residue)
    .unwrap()
}
fn input<'a>(frame: &'a Frame, genesis: &'a Declaration) -> Input<'a> {
    let markers = frame.closure.markers.markers();
    Input {
        frame,
        genesis,
        initial: &markers[0],
        terminal: markers
            .iter()
            .find(|m| m.identity().index == frame.parameters.boundary)
            .unwrap(),
    }
}
fn recognize(frame: &mut Frame) {
    frame.closure.markers = pn_records::test_support::burn::recognize(pn_records::test_support::burn::BurnCase {
        burn: frame.burn.clone(),
        policy: frame.marker_policy.clone(),
        history: frame.marker_history.clone(),
    })
    .unwrap();
}
// A component fixture profile with two equivalent, distinct opening proofs.
#[derive(Debug)]
struct OpeningVerifier;
impl burn::PublicVerifier for OpeningVerifier {
    fn profile(&self) -> &'static str {
        "fixture-public-v1"
    }
    fn destruction(&self, record: &burn::BurnRecord) -> bool {
        burn::PublicVerifier::destruction(&pn_records::test_support::burn::FixtureVerifier, record)
    }
    fn opening(&self, commitment: &[u8], opening: &burn::Opening) -> bool {
        let expected = format!("set:{}", opening.members.iter().cloned().collect::<Vec<_>>().join("|")).into_bytes();
        commitment == expected
            && [b"opening:".as_slice(), b"alternate:".as_slice()]
                .iter()
                .any(|prefix| opening.proof == [*prefix, commitment].concat())
    }
}
fn recognize_opening(frame: &mut Frame) {
    let burn = burn::validate_burn(frame.burn.clone()).unwrap();
    let mut declarations = packages().0.carrier().causes.declarations.clone();
    declarations
        .iter_mut()
        .find(|d| d.id.namespace == "marker" && d.id.name == "policy")
        .unwrap()
        .content = pn_records::constants::marker_policy_declaration(&frame.marker_policy, &burn).unwrap();
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let declarations = pn_records::validate_record(&[], &history, &declarations).unwrap();
    let policy = pn_records::constants::bind_marker_policy(&declarations, frame.marker_policy.clone(), &burn).unwrap();
    let history = burn::validate_marker_history(frame.marker_history.clone(), &policy, &OpeningVerifier).unwrap();
    frame.closure.markers = burn::recognize_markers(&history);
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
fn workspace() -> std::path::PathBuf {
    let mut path = std::env::current_dir().unwrap();
    loop {
        if path.join("packages/host/src/admitted_result/position/vectors.json").is_file() {
            return path;
        }
        assert!(path.pop(), "runtime workspace contains independent position corpus");
    }
}

fn vector_frame(name: &str, mut frame: Frame) -> Frame {
    match name {
        "initial-lineage" => frame.marker_history.markers[0].lineage = frame.marker_history.markers[1].lineage.clone(),
        "whole-prefix" => {
            frame.marker_policy.encoding = burn::Encoding::WholePrefixAcceptAll;
            for marker in &mut frame.marker_history.markers {
                marker.accepted = burn::AcceptedSet::WholePrefix;
            }
        }
        "commitment" => {
            frame.marker_policy.encoding = burn::Encoding::PublicCommitment;
            for marker in &mut frame.marker_history.markers {
                let burn::AcceptedSet::CompleteList(members) = &marker.accepted else {
                    panic!("fixture complete list");
                };
                let commitment = format!("set:{}", members.iter().cloned().collect::<Vec<_>>().join("|")).into_bytes();
                marker.accepted = burn::AcceptedSet::Commitment {
                    commitment: commitment.clone(),
                    openings: vec![burn::Opening {
                        members: members.clone(),
                        proof: [b"opening:".as_slice(), commitment.as_slice()].concat(),
                    }],
                };
            }
        }
        "set-order" => {
            let original = frame.marker_history.records[0].clone();
            for id in ["b", "aa"] {
                let mut alias = original.clone();
                alias.identity = id.into();
                frame.marker_history.records.push(alias);
                frame.marker_history.markers[1].lineage.insert(id.into());
            }
            frame.marker_history.markers[0].lineage.insert(original.identity);
            frame.marker_history.markers[1].accepted = burn::AcceptedSet::CompleteList(BTreeSet::from(["b".into(), "aa".into()]));
        }
        "utf8" => {
            frame.marker_history.identity = "histoire-λ".into();
            for marker in &mut frame.marker_history.markers {
                marker.history.clone_from(&frame.marker_history.identity);
            }
        }
        "root" | "ordinary" => {}
        _ => panic!("closed independent corpus"),
    }
    if name == "commitment" {
        recognize_opening(&mut frame);
    } else {
        recognize(&mut frame);
    }
    frame
}

fn encoded_position_disclosure(package: &AdmittedPackage, frame: Option<&Frame>) -> Vec<u8> {
    let mut disclosure = package.disclosures();
    if let Some(frame) = frame {
        let selected = disclosure.frames.last_mut().unwrap();
        selected.marker_policy = frame.marker_policy.clone();
        selected.marker_history = frame.marker_history.clone();
        selected.closure.markers.basis = frame.closure.markers.basis().clone();
        selected.closure.markers.markers = frame
            .closure
            .markers
            .markers()
            .iter()
            .map(|marker| d::Marker {
                identity: marker.identity().clone(),
                accepted: marker.accepted().clone(),
                destructions: marker.destructions().clone(),
            })
            .collect();
    }
    crate::publication::encode(&disclosure, &mut base::numeric(), d::Limits::default()).unwrap()
}

/// Claim: The private stored-span route reproduces the admitted route's complete projection bytes, computed residue and C on the seven independent position vectors without granting admission.
/// ´claim:history:tree-audit-span-position´
/// ´test:unit:tree-audit-span-position´
#[test]
fn tree_audit_span_position() {
    let (root, child) = packages();
    let root_input = Input::admitted(root).unwrap();
    let root_position = position(root, None);
    let root_package = encoded_position_disclosure(root, None);
    let root_spans = crate::storage::tree::server::spans::Validated::for_position_test(&root_package).unwrap();
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(workspace().join("packages/host/src/admitted_result/position/vectors.json")).unwrap(),
    )
    .unwrap();
    let rows = corpus.as_array().unwrap();
    assert_eq!(rows.len(), 7);
    for row in rows {
        let name = row["case"].as_str().unwrap();
        let mut frame = root_input.frame.clone();
        frame = vector_frame(name, frame);
        let (published, expected, expected_context, parent) = if name == "ordinary" {
            let child_input = Input::admitted(child).unwrap();
            let expected = bytes(&child_input, Some(&root_input), Some(root_position.residue()));
            let context = Builder {
                ceiling: usize::MAX,
                usage: &mut EncodingUsage::default(),
                reservation: &mut |_| Ok(()),
            }
            .context(
                child_input.genesis,
                &child_input.frame.marker_policy,
                child_input.initial,
                &child_input.frame.marker_history.records,
            )
            .unwrap();
            (
                encoded_position_disclosure(child, None),
                expected,
                context,
                Some((&root_spans, root_position.residue())),
            )
        } else {
            let selected = input(&frame, root_input.genesis);
            let expected = bytes(&selected, None, None);
            let context = Builder {
                ceiling: usize::MAX,
                usage: &mut EncodingUsage::default(),
                reservation: &mut |_| Ok(()),
            }
            .context(
                selected.genesis,
                &selected.frame.marker_policy,
                selected.initial,
                &selected.frame.marker_history.records,
            )
            .unwrap();
            (encoded_position_disclosure(root, Some(&frame)), expected, context, None)
        };
        let spans = crate::storage::tree::server::spans::Validated::for_position_test(&published).unwrap();
        let (residue, context, actual) =
            from_stored_spans(&spans, parent, usize::MAX, &mut EncodingUsage::default(), &mut |_| Ok(())).unwrap();
        assert_eq!(actual.len(), expected.len(), "projection length: {name}");
        if let Some(at) = actual.iter().zip(&expected).position(|(a, b)| a != b) {
            assert_eq!(actual[at], expected[at], "first projection byte at {at}: {name}");
        }
        assert_eq!(hex(&residue), row["residue"].as_str().unwrap(), "residue: {name}");
        assert_eq!(context, expected_context, "initial context: {name}");
    }
}

/// Claim: Seven distinct unsorted public projection inputs match independent canonical preimages and residues, including an admitted root and ordinary child; transition continuity is not fabricated.
/// ´claim:history:position-vectors´
/// ´test:unit:position-vectors´
#[test]
fn position_vectors() {
    let (root, child) = packages();
    let root_input = Input::admitted(root).unwrap();
    let parent = position(root, None);
    let child_position = position(child, Some(&parent));
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(workspace().join("packages/host/src/admitted_result/position/vectors.json")).unwrap(),
    )
    .unwrap();
    let rows = corpus.as_array().unwrap();
    let names: Vec<_> = rows.iter().map(|r| r["case"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 7);
    assert!(!names.windows(2).all(|w| w[0] < w[1]), "corpus reaches projection unsorted");
    let mut distinct = BTreeSet::new();
    for row in rows {
        let name = row["case"].as_str().unwrap();
        let mut frame = root_input.frame.clone();
        frame = vector_frame(name, frame);
        let canonical = if name == "ordinary" {
            let next = Input::admitted(child).unwrap();
            next.validate(Some(&root_input)).unwrap();
            bytes(&next, Some(&root_input), Some(parent.residue()))
        } else {
            let projection = input(&frame, root_input.genesis);
            projection.validate(None).unwrap();
            bytes(&projection, None, None)
        };
        if name == "commitment" {
            for marker in &mut frame.marker_history.markers {
                let burn::AcceptedSet::Commitment { commitment, openings } = &mut marker.accepted else {
                    unreachable!()
                };
                assert_ne!(
                    &openings[0].proof, commitment,
                    "commitment and opening proof are distinct inputs"
                );
                openings[0].proof = [b"alternate:".as_slice(), commitment.as_slice()].concat();
            }
            recognize_opening(&mut frame);
            let changed = input(&frame, root_input.genesis);
            changed.validate(None).unwrap();
            assert_eq!(
                canonical,
                bytes(&changed, None, None),
                "opening proof alone leaves the position equal"
            );
        }
        let mut framed = RECIPE.as_bytes().to_vec();
        framed.push(0);
        framed.extend_from_slice(&canonical);
        assert_eq!(
            hex(&canonical),
            row["canonical"].as_str().unwrap(),
            "independent canonical position preimage: {name}"
        );
        assert_eq!(
            hex(&framed),
            row["preimage"].as_str().unwrap(),
            "independent framed position preimage: {name}"
        );
        let digest = crate::storage::digest(RECIPE, &canonical);
        assert_eq!(
            hex(&digest),
            row["residue"].as_str().unwrap(),
            "independent position residue: {name}"
        );
        assert!(distinct.insert(canonical));
        if name == "root" {
            assert_eq!(parent.residue(), &digest);
        }
        if name == "ordinary" {
            assert_eq!(child_position.residue(), &digest);
        }
    }
    assert_eq!(distinct.len(), 7, "seven distinct projection inputs executed");
}

/// Claim: Position projection binds individual causal members and refuses invalid ordinary parent and acceptance shapes while evidence-only changes leave its bytes equal; transition shapes remain unsupported by the public carrier. The private genesis boundary refuses zero or multiple declarations, a guard unreachable through public admission.
/// ´claim:history:position-binding´
/// ´test:unit:position-binding´
#[test]
fn position_binding() {
    let (root, child) = packages();
    let initial = Input::admitted(root).unwrap();
    let next = Input::admitted(child).unwrap();
    let parent = position(root, None);
    let mut carrier = root.carrier().clone();
    carrier.causes.declarations.clear();
    assert!(
        matches!(Input::carrier(&carrier), Err(Error::InvalidPosition)),
        "private genesis guard refuses absence"
    );
    carrier.causes.declarations.push(initial.genesis.clone());
    assert_eq!(Input::carrier(&carrier).unwrap().genesis, initial.genesis);
    let mut later = initial.genesis.clone();
    later.id.edition += 1;
    later.effective_at += 1;
    for declarations in [[initial.genesis.clone(), later.clone()], [later, initial.genesis.clone()]] {
        carrier.causes.declarations = declarations.into();
        assert!(
            matches!(Input::carrier(&carrier), Err(Error::InvalidPosition)),
            "private genesis guard refuses multiple declarations regardless of effective point or carrier order"
        );
    }
    let baseline = bytes(&initial, None, None);
    let following = bytes(&next, Some(&initial), Some(parent.residue()));
    assert!(
        matches!(
            Position::from_package(child, None, RECIPE, usize::MAX, &mut EncodingUsage::default(), |_| Ok(())),
            Err(Error::InvalidPosition)
        ),
        "a later admitted package cannot become a root by omitting its parent"
    );
    assert_eq!(
        position(root, None).residue(),
        parent.residue(),
        "same public inputs determine position without store state"
    );
    let mut changed_parent = *parent.residue();
    changed_parent[0] ^= 1;
    assert_ne!(
        following,
        bytes(&next, Some(&initial), Some(&changed_parent)),
        "parent alone changes position"
    );
    let mut genesis = initial.genesis.clone();
    genesis.announced_at += 1;
    assert_ne!(
        baseline,
        bytes(&input(initial.frame, &genesis), None, None),
        "root context alone changes position"
    );
    assert_eq!(
        following,
        bytes(&input(next.frame, &genesis), Some(&initial), Some(parent.residue())),
        "inherited context enters only through parent"
    );
    for (name, change) in [
        ("policy", 0),
        ("placement", 1),
        ("lineage", 2),
        ("accepted", 3),
        ("proof", 4),
        ("label", 5),
        ("content", 6),
    ] {
        let mut frame = initial.frame.clone();
        match change {
            0 => frame.marker_policy.cadence.push('!'),
            1 => frame.marker_history.markers[1].history_position += 1,
            2 => {
                let mut record = frame.marker_history.records[0].clone();
                record.identity = "new".into();
                frame.marker_history.records.push(record);
                frame.marker_history.markers[1].lineage.insert("new".into());
            }
            3 => frame.marker_history.markers[1].accepted = burn::AcceptedSet::CompleteList(BTreeSet::new()),
            4 => frame.marker_history.records[0].evidence.push(0),
            5 => frame.marker_history.markers[1].name.push('!'),
            6 => frame.realization.provenance.push(0),
            _ => unreachable!(),
        }
        // Evidence mutations do not re-run admission: this is a projection-component control.
        if change != 4 {
            recognize(&mut frame);
        }
        let actual = bytes(&input(&frame, initial.genesis), None, None);
        if change < 4 {
            assert_ne!(baseline, actual, "{name} changes position");
        } else {
            assert_eq!(baseline, actual, "{name} is equal-position content");
        }
    }
    parent_refusals(&initial, &next);
    acceptance_refusals(&initial);
}

fn parent_refusals(initial: &Input<'_>, next: &Input<'_>) {
    assert_eq!(next.validate(None), Err(Error::InvalidPosition), "missing parent is refused");
    assert_eq!(
        initial.validate(Some(next)),
        Err(Error::InvalidPosition),
        "invalid ordinary parent is refused"
    );
    let mut regressed = next.frame.clone();
    for marker in &mut regressed.marker_history.markers {
        marker.accepted = burn::AcceptedSet::CompleteList(BTreeSet::new());
    }
    recognize(&mut regressed);
    assert_eq!(
        input(&regressed, next.genesis).validate(Some(initial)),
        Err(Error::InvalidPosition),
        "non-extending accepted increment refuses while lineage extends"
    );
    let mut lineage_parent = initial.frame.clone();
    for marker in &mut lineage_parent.marker_history.markers {
        marker.accepted = burn::AcceptedSet::CompleteList(BTreeSet::new());
    }
    recognize(&mut lineage_parent);
    for marker in &mut regressed.marker_history.markers {
        marker.lineage.clear();
    }
    recognize(&mut regressed);
    assert_eq!(
        input(&regressed, next.genesis).validate(Some(&input(&lineage_parent, initial.genesis))),
        Err(Error::InvalidPosition),
        "non-extending lineage refuses while accepted set extends"
    );
    let mut substitution = next.frame.clone();
    substitution.marker_history.records[0].address.0.push('!');
    assert_eq!(
        input(&substitution, next.genesis).validate(Some(initial)),
        Err(Error::InvalidPosition),
        "inherited lineage interpretation cannot be substituted"
    );
}

fn acceptance_refusals(initial: &Input<'_>) {
    let mut marker = initial.initial.identity().clone();
    let mut policy = initial.frame.marker_policy.clone();
    let empty = BTreeSet::new();
    let members = initial.terminal.accepted().clone();
    marker.lineage = members.clone();
    marker.accepted = burn::AcceptedSet::CompleteList(members.clone());
    assert_eq!(
        check_acceptance(&marker, &members, &policy, true),
        Err(Error::InvalidPosition),
        "nonempty initial recovered set refuses"
    );
    marker.lineage.clear();
    policy.encoding = burn::Encoding::PublicCommitment;
    marker.accepted = burn::AcceptedSet::Commitment {
        commitment: vec![1],
        openings: Vec::new(),
    };
    assert_eq!(
        check_acceptance(&marker, &empty, &policy, true),
        Err(Error::InvalidPosition),
        "opening must be unique"
    );
    marker.accepted = burn::AcceptedSet::Commitment {
        commitment: vec![1],
        openings: vec![
            burn::Opening {
                members: empty.clone(),
                proof: vec![1]
            };
            2
        ],
    };
    assert_eq!(
        check_acceptance(&marker, &empty, &policy, true),
        Err(Error::InvalidPosition),
        "two individually populated openings are not a unique opening"
    );
    marker.accepted = burn::AcceptedSet::Commitment {
        commitment: Vec::new(),
        openings: vec![burn::Opening {
            members: empty.clone(),
            proof: vec![1],
        }],
    };
    assert_eq!(
        check_acceptance(&marker, &empty, &policy, true),
        Err(Error::InvalidPosition),
        "empty published commitment refuses"
    );
    marker.accepted = burn::AcceptedSet::Commitment {
        commitment: vec![1],
        openings: vec![burn::Opening {
            members: empty.clone(),
            proof: Vec::new(),
        }],
    };
    assert_eq!(
        check_acceptance(&marker, &empty, &policy, true),
        Err(Error::InvalidPosition),
        "empty proof refuses"
    );
    marker.accepted = burn::AcceptedSet::CompleteList(empty.clone());
    assert_eq!(
        check_acceptance(&marker, &empty, &policy, true),
        Err(Error::InvalidPosition),
        "constructor must match policy"
    );
    policy.encoding = burn::Encoding::WholePrefixAcceptAll;
    marker.accepted = burn::AcceptedSet::WholePrefix;
    marker.lineage = members.clone();
    assert_eq!(
        check_acceptance(&marker, &members, &policy, true),
        Err(Error::InvalidPosition),
        "whole-prefix initial lineage must be empty"
    );
    assert_eq!(signed(u64::MAX), Err(Error::Representation(Representation::Range)));
    marker.history = "x".repeat(1024);
    assert_eq!(scope_range(&marker), Err(Error::Representation(Representation::Range)));
}

/// Claim: One meter observes construction and encoding requests, exact and one-below ceilings, every callback refusal position of one admitted root and panic usage; these are reservation controls, not an allocator census.
/// ´claim:history:position-budget´
/// ´test:unit:position-budget´
#[test]
fn position_budget() {
    let package = &packages().0;
    let mut usage = EncodingUsage::default();
    let mut requests = Vec::new();
    let result = Position::from_package(package, None, RECIPE, usize::MAX, &mut usage, |size| {
        requests.push(size);
        Ok(())
    })
    .unwrap();
    assert_eq!(usage.allocation_calls, requests.len());
    assert_eq!(usage.allocation_bytes, requests.iter().sum::<usize>());
    let total = usage.allocation_bytes;
    assert_eq!(
        Position::from_package(package, None, RECIPE, total, &mut usage, |_| Ok(()))
            .unwrap()
            .residue(),
        result.residue()
    );
    assert!(matches!(
        Position::from_package(package, None, RECIPE, total - 1, &mut usage, |_| Ok(())),
        Err(Error::Representation(Representation::Encoding(EncodingError::Limit)))
    ));
    for at in 0..requests.len() {
        let mut calls = 0;
        let refused = Position::from_package(package, None, RECIPE, total, &mut usage, |_| {
            let index = calls;
            calls += 1;
            if index == at { Err(()) } else { Ok(()) }
        });
        assert!(
            matches!(
                refused,
                Err(Error::Representation(Representation::Encoding(EncodingError::Reservation)))
            ),
            "callback refusal remains distinct at {at}"
        );
        assert_eq!(calls, at + 1);
        assert_eq!(usage.allocation_calls, at);
        assert_eq!(usage.allocation_bytes, requests[..at].iter().sum::<usize>());
    }
    let midway = requests.len() / 2;
    let mut remaining: usize = requests[..midway].iter().sum();
    let refused = Position::from_package(package, None, RECIPE, total, &mut usage, |size| {
        remaining = remaining.checked_sub(size).ok_or(())?;
        Ok(())
    });
    assert!(matches!(
        refused,
        Err(Error::Representation(Representation::Encoding(EncodingError::Reservation)))
    ));
    let mut calls = 0;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Position::from_package(package, None, RECIPE, total, &mut usage, |_| {
            assert_ne!(calls, midway, "callback panic");
            calls += 1;
            Ok(())
        });
    }));
    assert!(panic.is_err());
    assert_eq!(usage.allocation_calls, midway);
    assert_eq!(usage.allocation_bytes, requests[..midway].iter().sum::<usize>());
    assert!(matches!(
        Position::from_package(package, None, "unknown", total, &mut usage, |_| Ok(())),
        Err(Error::UnsupportedPositionRecipe)
    ));
    assert_eq!(usage.allocation_bytes, 0);
    assert_eq!(usage.allocation_calls, 0);
    count_refusal();
}

fn count_refusal() {
    let input = Input::admitted(&packages().0).unwrap();
    let mut frame = input.frame.clone();
    frame.marker_policy.cadence = "x".repeat(4096);
    let input = self::input(&frame, input.genesis);
    let mut usage = EncodingUsage::default();
    let mut reserve = |_| Ok(());
    let mut builder = Builder {
        ceiling: usize::MAX,
        usage: &mut usage,
        reservation: &mut reserve,
    };
    let value = builder.projection(&input, None, None).unwrap();
    let constructed = builder.usage.allocation_bytes;
    // Plenty of traversal storage, but less than this single text payload.
    builder.ceiling = constructed + 2048;
    assert_eq!(
        builder.encode(&value),
        Err(Error::Representation(Representation::Encoding(EncodingError::Length))),
        "measured-length refusal reaches carrier caller"
    );
    assert!(builder.usage.allocation_bytes >= constructed);
    assert_eq!(
        Error::from(EncodingError::Allocation),
        Error::Representation(Representation::Encoding(EncodingError::Allocation)),
        "allocator refusal conversion preserves its distinct cause"
    );
    assert_eq!(
        Error::from(TransferError::SpareCapacity),
        Error::Representation(Representation::Transfer(TransferError::SpareCapacity)),
        "transfer refusal is never normalized by shrinking"
    );
}

/// Claim: The tree carrier retains complete admitted package bytes and qualifies all four observation families by the computed result while retaining original declaration coordinates; the existing chain carrier is unchanged.
/// ´claim:history:tree-carrier-retention´
/// ´test:unit:tree-carrier-retention´
#[test]
fn tree_carrier_retention() {
    use crate::storage::Family;
    let (root, child) = packages();
    let parent = position(root, None);
    let next = position(child, Some(&parent));
    let limits = d::Limits {
        work: 100_000_000,
        arithmetic_steps: 5_000_000,
        ..d::Limits::default()
    };
    for p in [&parent, &next] {
        let retained = Retained::from_position(p, &mut base::numeric(), limits.clone()).unwrap();
        let chain = super::super::AdmittedEpoch::from_package(p.package, &mut base::numeric(), limits.clone()).unwrap();
        assert_eq!(retained.bytes(), chain.bytes(), "tree carrier retains every admitted byte");
        assert_eq!(retained.event().1, p.residue());
        assert_eq!(retained.event().2, p.parent());
        assert_eq!(retained.event().3, p.depth());
        let identity = hex(p.residue());
        let mut families = BTreeSet::new();
        for row in retained.declarations() {
            families.insert(row.version.family);
            match row.version.family {
                Family::Rule | Family::Constants => {
                    assert!(!row.version.key.contains(&identity));
                    let matching = chain
                        .declarations()
                        .iter()
                        .find(|old| {
                            old.version.family == row.version.family
                                && old.version.edition == row.version.edition
                                && old.version.payload == row.version.payload
                                && old.selected_at == row.selected_at
                        })
                        .unwrap();
                    assert_eq!(row.version.opens_at, matching.version.opens_at);
                    assert_eq!(row.version.announced_at, matching.version.announced_at);
                }
                _ => {
                    assert!(
                        row.version.key.contains(&format!("64:{identity}")),
                        "observation key names the result"
                    );
                    assert_eq!(row.version.edition, identity, "observation edition names the result");
                    assert_eq!(row.selected_at, p.depth());
                    assert_eq!(row.version.opens_at, p.depth());
                    assert_eq!(row.version.announced_at, p.depth());
                }
            }
        }
        assert_eq!(families.len(), 6);
    }
}
