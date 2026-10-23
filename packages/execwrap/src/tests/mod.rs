//! # `execwrap` library tests
//!
//! | Test                                                | What it covers                          |
//! |-----------------------------------------------------|-----------------------------------------|
//! | `routing_config_detects_combined_redirects`         | `--redirect` triggers both streams      |
//! | `routing_config_detects_single_stream_redirects`    | per-stream redirects only flag one      |
//! | `collect_file_specs_rejects_ambiguous_routing`      | conflicting paths are an error          |
//! | `aliased_redirection_paths_are_rejected`            | `a.log` vs `./a.log` conflict           |
//! | `symlink_and_hardlink_aliases_are_rejected`         | link aliases resolve to one identity    |
//! | `two_routes_to_one_log_are_refused_because_they_would_interleave` | filesystem identity prevents concurrent routes from overwriting one log |
//! | `parent_symlink_alias_is_rejected`                  | symlinked parent dirs resolve           |
//! | `symlinked_ancestor_with_missing_directories_is_rejected` | pending suffixes share identity   |
//! | `parent_dir_through_missing_component_still_resolves_symlinks` | `..` re-enters resolution    |
//! | `missing_directories_under_distinct_ancestors_validate` | distinct pending targets accepted  |
//! | `dangling_symlink_alias_is_rejected`                | dangling link aliases its target        |
//! | `dangling_symlink_chain_resolves_to_final_target`   | chains resolve to the last target       |
//! | `symlink_loop_is_an_error`                          | link loops error instead of hanging     |
//! | `distinct_redirection_targets_validate`             | different files remain accepted         |
//! | `ambiguous_alias_does_not_truncate_existing_output` | usage failure precedes truncation       |
//! | `dangling_alias_failure_leaves_target_intact`       | preflight only stats, never creates     |
//! | `typesetter_passes_data_through`                    | raw mode writes bytes unchanged         |
//! | `typesetter_preserves_arbitrary_bytes`              | raw mode is byte-exact on binary data   |
//! | `calligraphic_adds_prefix_per_line`                 | prefix mode formats per-line            |
//! | `calligraphic_sanitizes_control_bytes`              | sanitization is calligraphic-only       |
//! | `calligraphic_buffers_partial_lines_until_finalize` | partial lines flush at finalize         |
//! | `calligraphic_preserves_code_point_split_across_two_writes` | chunked multibyte UTF-8 survives |
//! | `calligraphic_preserves_code_point_split_across_three_writes` | byte-at-a-time UTF-8 survives  |
//! | `calligraphic_replaces_invalid_utf8_after_buffering` | genuinely invalid bytes still map to `\u{fffd}` |
//! | `calligraphic_output_is_chunking_invariant`         | same bytes, any chunking, same output   |

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::writer::{StreamProps, Writer};
use super::{ExecError, RoutingConfig, Stream, collect_file_specs, file_identity};

/// Claim: A combined redirect marks both stdout and stderr redirected, ensuring both child streams participate in routing.
/// ´claim:cli:routing-config-detects-combined-redirects´
/// ´test:crate:routing-config-detects-combined-redirects´
#[test]
fn routing_config_detects_combined_redirects() {
    let cfg = RoutingConfig {
        redirect: Some(PathBuf::from("a.log")),
        ..RoutingConfig::default()
    };
    assert!(cfg.is_stream_redirected(Stream::Stdout));
    assert!(cfg.is_stream_redirected(Stream::Stderr));
}

/// Claim: A stdout-only redirect marks stdout redirected and stderr unredirected, preserving independent stream routing.
/// ´claim:cli:routing-config-detects-single-stream-redirects´
/// ´test:crate:routing-config-detects-single-stream-redirects´
#[test]
fn routing_config_detects_single_stream_redirects() {
    let cfg = RoutingConfig {
        redirect_output: Some(PathBuf::from("out.log")),
        ..RoutingConfig::default()
    };
    assert!(cfg.is_stream_redirected(Stream::Stdout));
    assert!(!cfg.is_stream_redirected(Stream::Stderr));
}

/// Claim: Combined and stdout routes to the same path return `AmbiguousRedirection`, preventing competing writers to one destination.
/// ´claim:cli:collect-file-specs-rejects-ambiguous-routing´
/// ´test:crate:collect-file-specs-rejects-ambiguous-routing´
#[test]
fn collect_file_specs_rejects_ambiguous_routing() {
    let cfg = RoutingConfig {
        redirect: Some(PathBuf::from("a.log")),
        redirect_output: Some(PathBuf::from("a.log")),
        ..RoutingConfig::default()
    };
    let error = collect_file_specs(&cfg).expect_err("expected ambiguity");
    assert!(matches!(error, ExecError::AmbiguousRedirection { .. }));
}

/// Claim: A path and its dotted spelling are refused as ambiguous before routing, preventing lexical aliases from opening one log twice.
/// ´claim:cli:aliased-redirection-paths-are-rejected´
/// ´test:crate:aliased-redirection-paths-are-rejected´
#[test]
fn aliased_redirection_paths_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    let cfg = RoutingConfig {
        redirect: Some(dir.path().join("a.log")),
        redirect_output: Some(dir.path().join("./a.log")),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));
}

/// Claim: Routes to symlinked or hard-linked names of an existing log are refused and its bytes survive, protecting the prior log from truncation.
/// ´claim:cli:symlink-and-hardlink-aliases-are-rejected´
/// ´test:crate:symlink-and-hardlink-aliases-are-rejected´
#[test]
fn symlink_and_hardlink_aliases_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    let target = dir.path().join("a.log");
    std::fs::write(&target, b"keep").expect("write target");

    let symlink = dir.path().join("sym.log");
    std::os::unix::fs::symlink(&target, &symlink).expect("symlink");

    let symlinked = RoutingConfig {
        redirect: Some(target.clone()),
        redirect_output: Some(symlink),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&symlinked),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    let hard_link = dir.path().join("hard.log");
    std::fs::hard_link(&target, &hard_link).expect("hard link");

    let hard_linked = RoutingConfig {
        redirect: Some(target.clone()),
        redirect_error: Some(hard_link),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&hard_linked),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    // Preflight only stats: the existing target is untouched.
    assert_eq!(std::fs::read(&target).expect("read target"), b"keep");
}

/// Claim: Separately configured stdout and stderr paths sharing an inode are refused before truncation, preserving previous log bytes without claiming to close host races.
/// ´claim:cli:two-routes-to-one-log-are-refused-because-they-would-interleave´
/// ´test:crate:two-routes-to-one-log-are-refused-because-they-would-interleave´
#[test]
fn two_routes_to_one_log_are_refused_because_they_would_interleave() {
    // Routing uses filesystem identity rather than lexical output-role
    // comparison: two routes resolving to one file are opened independently,
    // each truncating, then written concurrently as the child produces
    // output. The log ends up interleaved and partially overwritten
    // while every I/O call succeeds.
    //
    // Lexical comparison cannot see this pair — the two names differ
    // in every component and neither is a `.`/`..` spelling of the
    // other — so refusing it needs the resolved identity.
    let dir = tempfile::tempdir().expect("tempdir");
    let stdout_log = dir.path().join("stdout.log");
    std::fs::write(&stdout_log, b"previous run").expect("write log");
    let stderr_log = dir.path().join("stderr.log");
    std::fs::hard_link(&stdout_log, &stderr_log).expect("hard link");

    let interleaving = RoutingConfig {
        redirect_output: Some(stdout_log.clone()),
        redirect_error: Some(stderr_log),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&interleaving),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    // The refusal precedes truncation, so the previous log survives.
    // Nothing here closes a host race: the check only precedes the
    // open, it does not hold the path still.
    assert_eq!(std::fs::read(&stdout_log).expect("read log"), b"previous run");
}

/// Claim: Two missing log paths under aliased existing parents are refused, preventing an absent final component from hiding destination identity.
/// ´claim:cli:parent-symlink-alias-is-rejected´
/// ´test:crate:parent-symlink-alias-is-rejected´
#[test]
fn parent_symlink_alias_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("create real dir");

    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink dir");

    // The target file does not exist yet; only the parents alias.
    let cfg = RoutingConfig {
        redirect: Some(real.join("x.log")),
        redirect_output: Some(alias.join("x.log")),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));
}

/// Claim: Aliased ancestors with two missing suffix directories still cause refusal before creating them, preventing lexical fallback from duplicating a log.
/// ´claim:cli:symlinked-ancestor-with-missing-directories-is-rejected´
/// ´test:crate:symlinked-ancestor-with-missing-directories-is-rejected´
#[test]
fn symlinked_ancestor_with_missing_directories_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("create real dir");

    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink dir");

    // Two missing directory levels below the symlinked ancestor:
    // canonicalizing the complete parent fails on both routes, so a
    // lexical fallback would accept them as distinct identities and
    // open one file under two routing kinds.
    let cfg = RoutingConfig {
        redirect: Some(real.join("new/sub/x.log")),
        redirect_output: Some(alias.join("new/sub/x.log")),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    // Rejection happens before any directory or file is created.
    assert!(!real.join("new").exists());
}

/// Claim: After a missing component and parent traversal, a symlinked component still resolves to the competing log and causes ambiguity refusal.
/// ´claim:cli:parent-dir-through-missing-component-still-resolves-symlinks´
/// ´test:crate:parent-dir-through-missing-component-still-resolves-symlinks´
#[test]
fn parent_dir_through_missing_component_still_resolves_symlinks() {
    let dir = tempfile::tempdir().expect("tempdir");

    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("create real dir");

    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink dir");

    // `newdir` does not exist; the `..` climbs back out of the missing
    // suffix, so the following symlinked component must be resolved
    // through the filesystem again, not appended lexically.
    let cfg = RoutingConfig {
        redirect: Some(dir.path().join("newdir/../alias/out.txt")),
        redirect_output: Some(real.join("out.txt")),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));
}

/// Claim: Two missing log suffixes under distinct existing ancestors produce two file specifications, allowing genuinely separate future destinations.
/// ´claim:cli:missing-directories-under-distinct-ancestors-validate´
/// ´test:crate:missing-directories-under-distinct-ancestors-validate´
#[test]
fn missing_directories_under_distinct_ancestors_validate() {
    let dir = tempfile::tempdir().expect("tempdir");

    let first = dir.path().join("first");
    let second = dir.path().join("second");
    std::fs::create_dir(&first).expect("create first dir");
    std::fs::create_dir(&second).expect("create second dir");

    let cfg = RoutingConfig {
        redirect_output: Some(first.join("new/sub/x.log")),
        redirect_error: Some(second.join("new/sub/x.log")),
        ..RoutingConfig::default()
    };

    let specs = collect_file_specs(&cfg).expect("distinct pending targets are valid");
    assert_eq!(specs.len(), 2);
}

/// Claim: A dangling link and its target conflict when routed together, while the link alone yields one valid specification, preserving single-target routing.
/// ´claim:cli:dangling-symlink-alias-is-rejected´
/// ´test:crate:dangling-symlink-alias-is-rejected´
#[test]
fn dangling_symlink_alias_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");

    // sym.log dangles: real.log does not exist. File::create on the
    // link would still create/truncate real.log, so the two paths are
    // one identity.
    let real = dir.path().join("real.log");
    let symlink = dir.path().join("sym.log");
    std::os::unix::fs::symlink(&real, &symlink).expect("symlink");

    let cfg = RoutingConfig {
        redirect_output: Some(symlink.clone()),
        redirect_error: Some(real),
        ..RoutingConfig::default()
    };

    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    // A dangling link on its own is still a valid single target.
    let alone = RoutingConfig {
        redirect_output: Some(symlink),
        ..RoutingConfig::default()
    };
    let specs = collect_file_specs(&alone).expect("single dangling target is valid");
    assert_eq!(specs.len(), 1);
}

/// Claim: A two-link dangling chain has the same identity as its missing final target, preventing chained aliases from evading route comparison.
/// ´claim:cli:dangling-symlink-chain-resolves-to-final-target´
/// ´test:crate:dangling-symlink-chain-resolves-to-final-target´
#[test]
fn dangling_symlink_chain_resolves_to_final_target() {
    let dir = tempfile::tempdir().expect("tempdir");

    let real = dir.path().join("real.log");
    let sym1 = dir.path().join("sym1.log");
    let sym2 = dir.path().join("sym2.log");
    std::os::unix::fs::symlink(&real, &sym1).expect("symlink sym1");
    std::os::unix::fs::symlink(&sym1, &sym2).expect("symlink sym2");

    assert_eq!(
        file_identity(&sym2).expect("chain identity"),
        file_identity(&real).expect("target identity"),
        "a dangling chain must share the final target's identity"
    );
}

/// Claim: A two-link cycle yields an identity error and an I/O preflight refusal, preventing unresolved cyclic paths from becoming log destinations.
/// ´claim:cli:symlink-loop-is-an-error´
/// ´test:crate:symlink-loop-is-an-error´
#[test]
fn symlink_loop_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");

    let loop_a = dir.path().join("loop_a.log");
    let loop_b = dir.path().join("loop_b.log");
    std::os::unix::fs::symlink(&loop_a, &loop_b).expect("symlink loop_b");
    std::os::unix::fs::symlink(&loop_b, &loop_a).expect("symlink loop_a");

    assert!(file_identity(&loop_a).is_err(), "a symlink loop must error, not hang");

    let cfg = RoutingConfig {
        redirect: Some(loop_a),
        ..RoutingConfig::default()
    };
    assert!(matches!(super::preflight_routing(&cfg), Err(ExecError::Io(_)),));
}

/// Claim: Separate stdout and stderr filenames pass preflight, preserving valid independent stream destinations.
/// ´claim:cli:distinct-redirection-targets-validate´
/// ´test:crate:distinct-redirection-targets-validate´
#[test]
fn distinct_redirection_targets_validate() {
    let dir = tempfile::tempdir().expect("tempdir");

    let cfg = RoutingConfig {
        redirect_output: Some(dir.path().join("out.log")),
        redirect_error: Some(dir.path().join("err.log")),
        ..RoutingConfig::default()
    };

    super::preflight_routing(&cfg).expect("distinct targets are valid");
}

/// Claim: A full run with aliased combined/stdout destinations returns `AmbiguousRedirection` and preserves the existing log, proving refusal precedes truncation.
/// ´claim:cli:ambiguous-alias-does-not-truncate-existing-output´
/// ´test:crate:ambiguous-alias-does-not-truncate-existing-output´
#[test]
fn ambiguous_alias_does_not_truncate_existing_output() {
    let dir = tempfile::tempdir().expect("tempdir");

    let target = dir.path().join("a.log");
    std::fs::write(&target, b"previous log contents").expect("write target");

    let symlink = dir.path().join("sym.log");
    std::os::unix::fs::symlink(&target, &symlink).expect("symlink");

    let cfg = RoutingConfig {
        redirect: Some(target.clone()),
        redirect_output: Some(symlink),
        ..RoutingConfig::default()
    };

    let command = [std::ffi::OsString::from("true")];

    assert!(matches!(
        super::run(&command, &cfg, |_notification| {}),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    assert_eq!(
        std::fs::read(&target).expect("read target"),
        b"previous log contents",
        "usage failure must precede any truncation"
    );
}

/// Claim: A dangling route pair is refused without creating its target and remains refused after creation, preserving existing bytes through preflight and run.
/// ´claim:cli:dangling-alias-failure-leaves-target-intact´
/// ´test:crate:dangling-alias-failure-leaves-target-intact´
#[test]
fn dangling_alias_failure_leaves_target_intact() {
    let dir = tempfile::tempdir().expect("tempdir");

    let real = dir.path().join("real.log");
    let symlink = dir.path().join("sym.log");
    std::os::unix::fs::symlink(&real, &symlink).expect("symlink");

    let cfg = RoutingConfig {
        redirect_output: Some(symlink),
        redirect_error: Some(real.clone()),
        ..RoutingConfig::default()
    };

    // Preflight only stats: rejecting the dangling alias must not
    // create the missing target.
    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));
    assert!(!real.exists(), "preflight must not create the target");

    // Once the target exists the alias is still rejected, and its
    // contents survive both preflight and a full run attempt.
    std::fs::write(&real, b"previous log contents").expect("write target");

    assert!(matches!(
        super::preflight_routing(&cfg),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    let command = [std::ffi::OsString::from("true")];
    assert!(matches!(
        super::run(&command, &cfg, |_notification| {}),
        Err(ExecError::AmbiguousRedirection { .. }),
    ));

    assert_eq!(
        std::fs::read(&real).expect("read target"),
        b"previous log contents",
        "usage failure must precede any truncation"
    );
}

struct SharedSink {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.inner.lock().expect("test sink lock");
        Write::write(&mut *guard, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn make_writer(add_prefix: bool, props: StreamProps, wrap_length: usize) -> (Writer, Arc<Mutex<Vec<u8>>>) {
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let shared = Arc::clone(&buffer);
    let sink = SharedSink { inner: shared };
    let writer = Writer::new(sink, add_prefix, wrap_length, props, false);
    (writer, buffer)
}

/// Claim: Raw output writes the two-line fixture unchanged through finalization, preserving byte content on the simple forwarding path.
/// ´claim:cli:typesetter-passes-data-through´
/// ´test:crate:typesetter-passes-data-through´
#[test]
fn typesetter_passes_data_through() {
    let (mut writer, buffer) = make_writer(false, StreamProps::default(), 80);
    writer.write(Stream::Stdout, b"hello\nworld\n").expect("write");
    writer.finalize().expect("finalize");
    let written = buffer.lock().expect("lock").clone();
    assert_eq!(&*written, b"hello\nworld\n");
}

/// Claim: Raw stdout and stderr preserve invalid UTF-8, NUL, control bytes and a 64 `KiB` payload exactly, protecting binary child output.
/// ´claim:cli:typesetter-preserves-arbitrary-bytes´
/// ´test:crate:typesetter-preserves-arbitrary-bytes´
#[test]
fn typesetter_preserves_arbitrary_bytes() {
    // Raw mode is byte-exact: invalid UTF-8, NUL, control bytes, and
    // large chunks pass through unchanged.
    let (mut writer, buffer) = make_writer(false, StreamProps::default(), 80);

    let mut payload: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x01, 0x1b, b'[', b'3', b'1', b'm'];
    payload.extend(std::iter::repeat_n(0xa5_u8, 64 * 1024));
    payload.push(b'\n');

    writer.write(Stream::Stdout, &payload).expect("write");
    writer.write(Stream::Stderr, &payload).expect("write");
    writer.finalize().expect("finalize");

    let written = buffer.lock().expect("lock").clone();
    let mut expected = payload.clone();
    expected.extend_from_slice(&payload);
    assert_eq!(written, expected);
}

/// Claim: Text presentation replaces NUL and invalid UTF-8 with the pinned printable forms and prefixes the line, preventing unsafe bytes from reaching that presentation.
/// ´claim:cli:calligraphic-sanitizes-control-bytes´
/// ´test:crate:calligraphic-sanitizes-control-bytes´
#[test]
fn calligraphic_sanitizes_control_bytes() {
    let props = StreamProps {
        line1_prefix_stdout: ">>> ".to_string(),
        ..StreamProps::default()
    };
    let (mut writer, buffer) = make_writer(true, props, 80);
    writer.write(Stream::Stdout, b"a\x00b\xffc\n").expect("write");
    writer.finalize().expect("finalize");
    let written = String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8");
    assert_eq!(written, ">>> a?b\u{fffd}c\n");
}

/// Claim: Two complete stdout lines each receive the configured prefix and retain their newline, preserving stream identification per line.
/// ´claim:cli:calligraphic-adds-prefix-per-line´
/// ´test:crate:calligraphic-adds-prefix-per-line´
#[test]
fn calligraphic_adds_prefix_per_line() {
    let props = StreamProps {
        line1_prefix_stdout: ">>> ".to_string(),
        wrap_prefix_stdout: "    ".to_string(),
        ..StreamProps::default()
    };
    let (mut writer, buffer) = make_writer(true, props, 80);
    writer.write(Stream::Stdout, b"line one\nline two\n").expect("write");
    writer.finalize().expect("finalize");
    let written = String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8");
    assert_eq!(written, ">>> line one\n>>> line two\n");
}

/// Claim: An incomplete line produces no immediate bytes and finalization emits its prefix and newline, preserving complete-line presentation.
/// ´claim:cli:calligraphic-buffers-partial-lines-until-finalize´
/// ´test:crate:calligraphic-buffers-partial-lines-until-finalize´
#[test]
fn calligraphic_buffers_partial_lines_until_finalize() {
    let props = StreamProps {
        line1_prefix_stdout: ">>> ".to_string(),
        ..StreamProps::default()
    };
    let (mut writer, buffer) = make_writer(true, props, 80);
    writer.write(Stream::Stdout, b"partial").expect("write");
    assert!(buffer.lock().expect("lock").is_empty());
    writer.finalize().expect("finalize");
    let written = String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8");
    assert_eq!(written, ">>> partial\n");
}

fn prefix_props() -> StreamProps {
    StreamProps {
        line1_prefix_stdout: ">>> ".to_string(),
        ..StreamProps::default()
    }
}

/// Claim: A euro sign split after its first UTF-8 byte renders intact after the second write, preventing pipe chunk boundaries from corrupting text.
/// ´claim:cli:calligraphic-preserves-code-point-split-across-two-writes´
/// ´test:crate:calligraphic-preserves-code-point-split-across-two-writes´
#[test]
fn calligraphic_preserves_code_point_split_across_two_writes() {
    // "€\n" is E2 82 AC 0A; a pipe read may deliver any split of it.
    let (mut writer, buffer) = make_writer(true, prefix_props(), 80);
    writer.write(Stream::Stdout, &[0xe2]).expect("write");
    writer.write(Stream::Stdout, &[0x82, 0xac, b'\n']).expect("write");
    writer.finalize().expect("finalize");
    let written = String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8");
    assert_eq!(written, ">>> \u{20ac}\n");
}

/// Claim: Delivering each euro-sign byte separately still renders the exact prefixed character, protecting multibyte text under minimal reads.
/// ´claim:cli:calligraphic-preserves-code-point-split-across-three-writes´
/// ´test:crate:calligraphic-preserves-code-point-split-across-three-writes´
#[test]
fn calligraphic_preserves_code_point_split_across_three_writes() {
    let (mut writer, buffer) = make_writer(true, prefix_props(), 80);
    for byte in [0xe2_u8, 0x82, 0xac, b'\n'] {
        writer.write(Stream::Stdout, &[byte]).expect("write");
    }
    writer.finalize().expect("finalize");
    let written = String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8");
    assert_eq!(written, ">>> \u{20ac}\n");
}

/// Claim: A lone continuation byte and a final truncated sequence render replacement characters at the pinned positions, distinguishing invalid input from merely split UTF-8.
/// ´claim:cli:calligraphic-replaces-invalid-utf8-after-buffering´
/// ´test:crate:calligraphic-replaces-invalid-utf8-after-buffering´
#[test]
fn calligraphic_replaces_invalid_utf8_after_buffering() {
    // A lone continuation byte and a truncated sequence at end of
    // stream are genuinely invalid and must still become U+FFFD.
    let (mut writer, buffer) = make_writer(true, prefix_props(), 80);
    writer.write(Stream::Stdout, &[b'a', 0xac]).expect("write");
    writer.write(Stream::Stdout, b"b\n").expect("write");
    writer.write(Stream::Stdout, &[0xe2, 0x82]).expect("write");
    writer.finalize().expect("finalize");
    let written = String::from_utf8(buffer.lock().expect("lock").clone()).expect("utf8");
    assert_eq!(written, ">>> a\u{fffd}b\n>>> \u{fffd}\n");
}

/// Claim: The multilingual fixture renders identically for six chunk sizes, retaining the euro sign without replacement characters, protecting presentation from read boundaries.
/// ´claim:cli:calligraphic-output-is-chunking-invariant´
/// ´test:crate:calligraphic-output-is-chunking-invariant´
#[test]
fn calligraphic_output_is_chunking_invariant() {
    // The same byte stream must render identically no matter how the
    // OS chunks the pipe reads.
    let payload = "una línea con € y 日本語\nsecond line\ntail without newline"
        .as_bytes()
        .to_vec();

    let mut renderings = Vec::new();
    for chunk_size in [1_usize, 2, 3, 5, 7, payload.len()] {
        let (mut writer, buffer) = make_writer(true, prefix_props(), 80);
        for chunk in payload.chunks(chunk_size) {
            writer.write(Stream::Stdout, chunk).expect("write");
        }
        writer.finalize().expect("finalize");
        renderings.push(buffer.lock().expect("lock").clone());
    }

    let first = renderings[0].clone();
    assert!(
        renderings.iter().all(|rendering| *rendering == first),
        "output depends on write chunking"
    );
    let text = String::from_utf8(first).expect("utf8");
    assert!(text.contains('\u{20ac}'));
    assert!(!text.contains('\u{fffd}'));
}

/// Claim: Running a real child through argument capture, progress and pipe relay builds no byte payload at default; the same sites build payloads at trace while preserving the child's exact output and exit.
/// ´claim:cli:default-execwrap-sites-do-not-build-payloads´
/// ´test:crate:default-payload-sites´
#[test]
fn default_payload_sites() {
    if let Ok(mode) = std::env::var("PN_TEST_PAYLOAD_SITES") {
        let _guard = cli_common::observation::bootstrap(true, false, tracing::Level::INFO).unwrap();
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        let error = root.path().join("error");
        let config = RoutingConfig {
            redirect_output: Some(output.clone()),
            redirect_error: Some(error.clone()),
            ..Default::default()
        };
        let result = super::run(
            &[
                "sh".into(),
                "-c".into(),
                "printf public; printf diagnostic >&2; exit 7".into(),
            ],
            &config,
            |_| {},
        )
        .unwrap();
        assert_eq!(result.exit_code, 7);
        assert_eq!(std::fs::read(output).unwrap(), b"public");
        assert_eq!(std::fs::read(error).unwrap(), b"diagnostic");
        let builds = super::PAYLOAD_BUILDS.load(std::sync::atomic::Ordering::Relaxed);
        if mode == "default" {
            assert_eq!(builds, 0);
        } else {
            assert!(builds >= 7);
        }
    } else {
        for mode in ["default", "trace"] {
            let root = tempfile::tempdir().unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::default_payload_sites"])
                .env("PN_TEST_PAYLOAD_SITES", mode)
                .env("PN_OBSERVE_LEVEL", mode)
                .env("PN_OBSERVE_ARTIFACT_DIR", root.path())
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{} {}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
