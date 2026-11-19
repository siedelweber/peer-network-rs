use super::{AuditBudget, AuditFailure, AuditInventory, AuditMeter, AuditUsage, result_location};
use crate::storage::{
    StorageError,
    tree::{
        Error, Generation, MemoryTree, Usage,
        tests::{budget, declared, forks, snapshot},
    },
};
use pn_interchange::{Array, Value};

fn allowance() -> AuditBudget {
    AuditBudget {
        page_rows: 64,
        rows: 100_000_000,
        allocation_bytes: 1_000_000_000,
        retained_bytes: 1_000_000_000,
        items: 10_000_000,
    }
}

fn fields(value: &Value) -> &[Value] {
    let Value::Array(array) = value else {
        panic!("expected logical record")
    };
    array.as_slice()
}

fn slots(value: &Value) -> usize {
    1 + match value {
        Value::Array(array) => array.as_slice().iter().map(slots).sum(),
        _ => 0,
    }
}

fn install<'a>(tree: &mut MemoryTree<'a>, generation: &'a Generation) {
    assert_eq!(tree.install_generation(generation, budget(), &mut Usage::default()), Ok(true));
}

fn history(name: &str) -> Generation {
    let mut declaration = declared();
    let old = "5:1:h1:p1:e1:s1:k";
    let key = format!("5:{}:{name}1:p1:e1:s1:k", name.len());
    declaration.scope.history = name.to_owned();
    for version in &mut declaration.versions {
        version.key = key.clone();
    }
    for closure in &mut declaration.closures {
        closure.key = key.clone();
    }
    assert_ne!(key, old);
    declaration
}

fn expected_declaration(declaration: &Generation) -> Value {
    let key = format!("4:{}:{}1:p1:e1:s", declaration.scope.history.len(), declaration.scope.history);
    let version = |row: &crate::storage::Version| {
        let payload = if let Some(payload) = &row.payload {
            let (digest, disclosure) = payload.commitments();
            Value::Array(Array::new([
                Value::Unsigned(1),
                Value::Bytes(payload.bytes().to_vec().into()),
                Value::Bytes(digest.to_vec().into()),
                disclosure.map_or(Value::Null, |value| Value::Bytes(value.to_vec().into())),
            ]))
        } else {
            Value::Null
        };
        Value::Array(Array::new([
            Value::Unsigned(1),
            Value::Text(row.key.clone().into()),
            Value::Text(row.edition.clone().into()),
            Value::Unsigned(row.announced_at),
            Value::Unsigned(row.opens_at),
            payload,
        ]))
    };
    let versions = declaration.versions.iter().map(&version).collect::<Vec<_>>();
    let closures = declaration
        .closures
        .iter()
        .map(|row| {
            Value::Array(Array::new([
                Value::Unsigned(1),
                Value::Text(row.key.clone().into()),
                Value::Text(row.edition.clone().into()),
                Value::Unsigned(row.closes_at),
            ]))
        })
        .collect::<Vec<_>>();
    let generation = Value::Array(Array::new([
        Value::Text(key.clone().into()),
        Value::Unsigned(1),
        Value::Null,
        Value::Unsigned(1),
        Value::Text(String::from("unstable").into()),
        Value::Array(Array::new(versions)),
        Value::Array(Array::new(closures)),
    ]));
    let histories = declaration
        .versions
        .iter()
        .map(|row| {
            let close = declaration
                .closures
                .iter()
                .find(|closure| closure.key == row.key && closure.edition == row.edition)
                .map_or(Value::Null, |closure| Value::Unsigned(closure.closes_at));
            Value::Array(Array::new([
                version(row),
                Value::Array(Array::new([Value::Array(Array::new([
                    Value::Text(key.clone().into()),
                    Value::Unsigned(1),
                    Value::Unsigned(row.opens_at),
                    close,
                ]))])),
            ]))
        })
        .collect::<Vec<_>>();
    Value::Array(Array::new([
        Value::Array(Array::new([generation])),
        Value::Array(Array::new(histories)),
        Value::Array(Array::new([])),
        Value::Array(Array::new([])),
    ]))
}

fn audit(tree: &MemoryTree<'_>) -> AuditInventory {
    tree.audit(allowance(), &mut AuditUsage::default())
        .expect("complete fixture audit")
}

/// Claim: Empty and declaration-only histories retain all versions and closures in framed scope order with exact occurrence counts.
/// ´claim:history:tree-audit-memory-domains´
/// ´test:unit:tree-audit-memory-domains´
#[test]
fn tree_audit_memory_domains() {
    let empty = audit(&MemoryTree::default());
    assert_eq!(empty.counts(), (0, 0, 0, 0, 0, 5));
    assert_eq!(
        empty.fields(),
        &Value::Array(Array::new([
            Value::Array(Array::new([])),
            Value::Array(Array::new([])),
            Value::Array(Array::new([])),
            Value::Array(Array::new([])),
        ]))
    );
    let aa = history("aa");
    let b = history("b");
    let mut tree = MemoryTree::default();
    install(&mut tree, &aa);
    install(&mut tree, &b);
    let actual = audit(&tree);
    assert_eq!(actual.counts().0, 2);
    assert_eq!(actual.counts().1, 4);
    assert_eq!(actual.counts().2, 0);
    let generation_rows = fields(&fields(actual.fields())[0]);
    assert_eq!(
        fields(&generation_rows[0])[0],
        Value::Text(String::from("4:1:b1:p1:e1:s").into())
    );
    assert_eq!(
        fields(&generation_rows[1])[0],
        Value::Text(String::from("4:2:aa1:p1:e1:s").into())
    );
    let expected_b = expected_declaration(&b);
    let expected_aa = expected_declaration(&aa);
    let expected = Value::Array(Array::new([
        Value::Array(Array::new([
            fields(&fields(&expected_b)[0])[0].clone(),
            fields(&fields(&expected_aa)[0])[0].clone(),
        ])),
        Value::Array(Array::new(
            fields(&fields(&expected_b)[1])
                .iter()
                .chain(fields(&fields(&expected_aa)[1]))
                .cloned(),
        )),
        Value::Array(Array::new([])),
        Value::Array(Array::new([])),
    ]));
    assert_eq!(actual.fields(), &expected);
    assert_eq!(
        actual.counts().5,
        5 + slots(&fields(&expected_b)[0]) - 1 + slots(&fields(&expected_b)[1]) - 1 + slots(&fields(&expected_aa)[0]) - 1
            + slots(&fields(&expected_aa)[1])
            - 1
    );
    let payload = aa.versions[0].payload.as_ref().unwrap().bytes().len();
    assert_eq!(actual.counts().4, 416 + 4 * payload);
}

fn fork_tree(main_first: bool) -> MemoryTree<'static> {
    let fixture = forks();
    let mut tree = MemoryTree::default();
    install(&mut tree, &fixture.generation);
    let siblings = if main_first {
        [&fixture.main[2], &fixture.side_debit[2]]
    } else {
        [&fixture.side_debit[2], &fixture.main[2]]
    };
    for input in [
        &fixture.main[0],
        &fixture.main[1],
        siblings[0],
        siblings[1],
        &fixture.main[3],
        &fixture.other_root[0],
    ] {
        assert_eq!(
            tree.commit(input, Some("unstable"), budget(), &mut Usage::default())
                .map(|j| j.inserted),
            Ok(true)
        );
    }
    tree
}

/// Claim: Two sibling arrival orders yield one complete logical inventory with both roots, exact packages and independent origins.
/// ´claim:history:tree-audit-memory-forks´
/// ´test:unit:tree-audit-memory-forks´
#[test]
fn tree_audit_memory_forks() {
    let first = fork_tree(true);
    let second = fork_tree(false);
    let a = audit(&first);
    let b = audit(&second);
    assert_eq!(a, b);
    assert_eq!(a.counts().3, 6);
    let scopes = fields(&fields(a.fields())[2]);
    assert_eq!(scopes.len(), 1);
    assert_eq!(fields(&fields(&scopes[0])[2]).len(), 2);
    let results = fields(&fields(a.fields())[3]);
    for input in [
        &forks().main[0],
        &forks().main[1],
        &forks().main[2],
        &forks().main[3],
        &forks().side_debit[2],
        &forks().other_root[0],
    ] {
        let row = results
            .iter()
            .find(|row| fields(row)[1] == Value::Bytes(input.event().1.to_vec().into()))
            .unwrap();
        assert_eq!(fields(row)[4], Value::Bytes(input.bytes().to_vec().into()));
        for selection in fields(&fields(row)[7]) {
            let chosen = fields(selection);
            let use_ = input
                .declarations()
                .iter()
                .find(|use_| {
                    let version = fields(&chosen[1]);
                    version[1] == Value::Text(use_.version.key.clone().into())
                        && version[2] == Value::Text(use_.version.edition.clone().into())
                        && chosen[0] == Value::Unsigned(use_.selected_at)
                })
                .unwrap();
            let recorded = first.results.get(&(input.event().0, *input.event().1)).unwrap();
            let origin = recorded
                .references
                .iter()
                .find(|reference| reference.use_ == use_)
                .unwrap()
                .origin;
            assert_eq!(chosen[2], Value::Bytes(origin.to_vec().into()));
        }
    }
    for (input, origin) in [
        (&forks().main[2], forks().main[2].event().1),
        (&forks().side_debit[2], forks().side_debit[2].event().1),
        (&forks().main[3], forks().main[2].event().1),
    ] {
        let row = results
            .iter()
            .find(|row| fields(row)[1] == Value::Bytes(input.event().1.to_vec().into()))
            .unwrap();
        let debit = fields(&fields(row)[8])
            .iter()
            .find(|debit| fields(&fields(debit)[0])[1] == Value::Unsigned(3))
            .unwrap();
        assert_eq!(fields(debit)[1], Value::Bytes(origin.to_vec().into()));
    }
}

/// Claim: On the orphan fixture, independent enumeration preserves `CorruptHistory` and its complete observed key at the allocation ceiling; diagnostic publication uses only its initial reservation.
/// ´claim:history:tree-audit-memory-orphan´
/// ´test:unit:tree-audit-memory-orphan´
#[test]
fn tree_audit_memory_orphan() {
    let mut tree = fork_tree(true);
    audit(&tree);
    let fixture = forks();
    let root = &fixture.main[0];
    let expected_identity = [
        &fixture.main[0],
        &fixture.main[1],
        &fixture.main[2],
        &fixture.main[3],
        &fixture.side_debit[2],
        &fixture.other_root[0],
    ]
    .iter()
    .map(|input| *input.event().1)
    .min()
    .expect("nonempty fixture");
    let before = snapshot(&tree);
    tree.scopes.erase(&root.event().0);
    assert_ne!(snapshot(&tree), before);
    let damaged = snapshot(&tree);
    let mut usage = AuditUsage::default();
    let refusal = tree.audit(allowance(), &mut usage);
    let Err(AuditFailure::Refused {
        error: Error::Storage(StorageError::CorruptHistory),
        location,
    }) = refusal
    else {
        panic!("orphan must retain its corruption cause")
    };
    assert_eq!(location.relation(), Some("pn_epoch_results"));
    assert_eq!(location.key_len(), 2);
    assert_eq!(location.key_text(0), Some("4:7:history6:policy1:18:sequence"));
    assert_eq!(location.key_bytes(1), Some(expected_identity.as_slice()));
    assert_eq!(location.key_integer(0), None);
    assert!(!location.is_not_read() && !location.is_over_bound());
    let mut exact = allowance();
    exact.allocation_bytes = usage.allocation_bytes;
    let mut exact_usage = AuditUsage::default();
    let Err(AuditFailure::Refused {
        error: Error::Storage(StorageError::CorruptHistory),
        location: exact_location,
    }) = tree.audit(exact, &mut exact_usage)
    else {
        panic!("orphan must retain its cause at the observed allocation ceiling")
    };
    assert_eq!(exact_location, location);
    assert_eq!(exact_usage.allocation_bytes, exact.allocation_bytes);

    let mut meter = AuditMeter::new(AuditBudget {
        allocation_bytes: 2127,
        ..allowance()
    });
    meter
        .begin(AuditBudget {
            allocation_bytes: 2127,
            ..allowance()
        })
        .unwrap();
    let backing = meter.diagnostic.as_ptr();
    let capacity = meter.diagnostic.capacity();
    let before = meter.usage();
    let AuditFailure::Refused {
        error: Error::Storage(StorageError::CorruptHistory),
        location: direct,
    } = meter.refused(
        StorageError::CorruptHistory,
        result_location(root.event().0, expected_identity),
    )
    else {
        panic!("diagnostic publication must keep the cause")
    };
    assert_eq!(meter.usage(), before);
    assert_eq!(direct.backing.as_ptr(), backing);
    assert_eq!(direct.backing.capacity(), capacity);
    assert_eq!(direct, location);
    assert_eq!(snapshot(&tree), damaged);
}

/// Claim: Four separate allowance shortages refuse cumulatively without mutation; a new sufficient invocation returns the expected full inventory.
/// ´claim:history:tree-audit-memory-limit´
/// ´test:unit:tree-audit-memory-limit´
#[test]
fn tree_audit_memory_limit() {
    let declaration = history("b");
    let mut tree = MemoryTree::default();
    install(&mut tree, &declaration);
    let before = snapshot(&tree);
    for ceiling in [
        AuditBudget { rows: 0, ..allowance() },
        AuditBudget {
            allocation_bytes: 0,
            ..allowance()
        },
        AuditBudget {
            retained_bytes: 0,
            ..allowance()
        },
        AuditBudget { items: 5, ..allowance() },
    ] {
        let mut usage = AuditUsage::default();
        assert!(matches!(
            tree.audit(ceiling, &mut usage),
            Err(AuditFailure::Refused {
                error: Error::Storage(StorageError::ReadLimit),
                ..
            })
        ));
        assert_eq!(snapshot(&tree), before);
        assert!(usage.allocation_bytes <= ceiling.allocation_bytes);
        assert!(usage.rows <= ceiling.rows);
        assert!(usage.retained_bytes <= ceiling.retained_bytes);
        assert!(usage.items <= ceiling.items);
        if ceiling.retained_bytes == 0 || ceiling.items == 5 {
            assert!(usage.rows > 0);
            assert!(usage.allocation_bytes > 2127);
            assert!(usage.allocation_requests > 1);
        }
    }
    assert_eq!(audit(&tree).fields(), &expected_declaration(&declaration));
}

/// Claim: A sibling substituted as one inherited selected-use origin is a semantic corruption, with no partial inventory or mutation.
/// ´claim:history:tree-audit-memory-content´
/// ´test:unit:tree-audit-memory-content´
#[test]
fn tree_audit_memory_content() {
    let mut tree = fork_tree(true);
    audit(&tree);
    let child = &forks().main[3];
    let node = tree.results.get_mut(&(child.event().0, *child.event().1)).unwrap();
    let chosen = node
        .references
        .iter_mut()
        .find(|selection| super::super::unqualified(selection.use_.version.family))
        .unwrap();
    let selected = chosen.use_;
    chosen.origin = *forks().side_debit[2].event().1;
    let damaged = snapshot(&tree);
    let refusal = tree.audit(allowance(), &mut AuditUsage::default());
    let Err(AuditFailure::Refused {
        error: Error::Storage(StorageError::CorruptHistory),
        location,
    }) = refusal
    else {
        panic!("inherited selection must refuse")
    };
    assert_eq!(location.relation(), Some("pn_epoch_references"));
    assert_eq!(location.key_len(), 5);
    assert_eq!(location.key_text(0), Some("4:7:history6:policy1:18:sequence"));
    assert_eq!(location.key_bytes(1), Some(child.event().1.as_slice()));
    assert_eq!(location.key_integer(2), Some(i128::from(selected.selected_at)));
    assert_eq!(location.key_text(3), Some(selected.version.family.name()));
    assert_eq!(location.key_text(4), Some(selected.version.key.as_str()));
    assert_eq!(snapshot(&tree), damaged);
}
