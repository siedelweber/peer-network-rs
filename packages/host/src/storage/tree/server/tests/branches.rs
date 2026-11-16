use super::super::super::{Closure, tests::retain_chain};
use super::*;
use crate::admitted_carrier_tests::tree_fixture::tree_sequence;
use crate::admitted_result::position::Retained;

async fn read(store: &mut ServerTree, tip: &Retained, wanted: &Retained, exact: bool) -> (ServerResult, Usage) {
    let mut reader = store.reader(allowance()).await.unwrap();
    let result = if exact {
        reader.exact(wanted.event().0, *wanted.event().1).await
    } else {
        reader.as_of(tip.event().0, *tip.event().1, wanted.event().3).await
    };
    assert!(result.is_ok(), "server branch read remains valid: {result:?}");
    let result = result.unwrap().unwrap();
    assert_eq!(result.identity, *wanted.event().1, "server read names the requested ancestor");
    (result, reader.usage())
}

pub(super) async fn run() {
    let main = retain_chain(&tree_sequence(
        &[100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200],
        None,
    ));
    let side = retain_chain(&tree_sequence(&[100, 200, 301, 401, 501, 601], None));
    let nested = retain_chain(&tree_sequence(&[100, 200, 301, 402, 502, 602], None));
    let f = forks();
    let mut model = MemoryTree::default();
    model
        .install_generation(&f.generation, allowance(), &mut Usage::default())
        .unwrap();
    for input in &main[..3] {
        model
            .commit(input, Some("unstable"), allowance(), &mut Usage::default())
            .unwrap();
    }
    install(&model, &f.generation, "storage-tree-reads.json").await;
    let mut store = ServerTree::open(session().await).await.unwrap();
    let before_exact = read(&mut store, &main[2], &main[1], true).await;
    let before_as_of = read(&mut store, &main[2], &main[1], false).await;
    for input in side.iter().skip(2).chain(nested.iter().skip(3)).chain(main.iter().skip(3)) {
        model
            .commit(input, Some("unstable"), allowance(), &mut Usage::default())
            .unwrap();
    }
    install(&model, &f.generation, "storage-tree-reads.json").await;
    assert_eq!(
        read(&mut store, &main[11], &main[1], true).await,
        before_exact,
        "later results leave complete exact read and usage unchanged"
    );
    assert_eq!(
        read(&mut store, &main[11], &main[1], false).await,
        before_as_of,
        "whole server read ignores empty length and side branches"
    );
    let side_usage = read(&mut store, &side[5], &main[1], false).await.1;
    let nested_usage = read(&mut store, &nested[5], &main[1], false).await.1;
    assert!(
        before_as_of.1.rows < side_usage.rows && side_usage.rows < nested_usage.rows,
        "descriptor work grows only along the named nested path"
    );
    for depth in [6, 2, 4, 1, 5, 3] {
        let expected = if depth <= 2 { &main[depth - 1] } else { &nested[depth - 1] };
        read(&mut store, &nested[5], expected, false).await;
    }
    for depth in [11, 4, 8, 3, 7] {
        read(&mut store, &main[11], &main[depth - 1], false).await;
    }
    closure().await;
}

async fn closure() {
    let f = forks();
    let mut generation = f.generation.clone();
    let selected = f.main[0]
        .declarations()
        .iter()
        .find(|u| u.version.family == Family::Rule)
        .unwrap();
    let mut later = selected.version.clone();
    later.edition.push_str("-later");
    later.opens_at = f
        .main
        .iter()
        .chain(&f.side)
        .flat_map(Retained::declarations)
        .filter(|u| u.version.family == selected.version.family && u.version.key == selected.version.key)
        .map(|u| u.selected_at)
        .max()
        .unwrap()
        + 1;
    generation.closures.push(Closure {
        family: selected.version.family,
        key: selected.version.key.clone(),
        edition: selected.version.edition.clone(),
        closes_at: later.opens_at,
    });
    generation.versions.push(later);
    generation
        .versions
        .sort_unstable_by(|a, b| super::super::super::declaration_key(a).cmp(&super::super::super::declaration_key(b)));
    let mut model = MemoryTree::default();
    model
        .install_generation(&generation, allowance(), &mut Usage::default())
        .unwrap();
    for input in [&f.main[0], &f.main[1], &f.side[2], &f.main[2], &f.main[3]] {
        model
            .commit(input, Some("unstable"), allowance(), &mut Usage::default())
            .unwrap();
    }
    install(&model, &generation, "storage-tree-reads.json").await;
    let mut store = ServerTree::open(session().await).await.unwrap();
    let (got, _) = read(&mut store, &f.main[3], &f.main[3], true).await;
    assert!(
        got.selections.iter().any(|s| s.use_ == *selected),
        "server retains the as-of edition rather than a current declaration"
    );
}
