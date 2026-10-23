# `execwrap` · `guide:execwrap:execwrap`

`execwrap` runs a child process and routes its stdout and stderr to log files. Callers choose the child command and the destinations for its output.

The package is both a library and the `execwrap` binary. The binary implements the command-line output contract (`[ROOT-rec:output:decision]`) through `cli-common`.

## Execution trust boundary · `sec:execwrap:execution-trust-boundary`

`execwrap` is **not a sandbox**. Read this before using it on anything you do not already trust:

- The caller authorizes the selected child executable to run with the operating-system authority of this process. Nothing is dropped, filtered, or confined.
- Child arguments are public inputs and are observed in full, including their byte representation. Passing instance-private material through this untyped process interface is not an admitted secret integration; explicit exposure consumers remain held under (`[ROOT-inv:observe:secret-boundary]`).
- Relayed and captured child output is **unsanitized child result data** (the child-byte relay exception in (`[ROOT-rec:output:decision]`)). Observation records the full byte payload without rewriting it. In raw routing the result is written byte-for-byte.
- Wrapper observations include the public program path, full arguments, child pid, results and byte payloads; the observation queue reports loss without changing child results.

`--observation enabled|disabled` selects collection, with enabled as the default. Disabled collection emits one unavailable-status record; neither setting changes child stdout bytes or exit status.

## Routing model · `sec:execwrap:routing-model`

Four destinations, each optional:

|Target|Captures|
|------|--------|
|`redirect`|stdout and stderr, merged, raw|
|`redirect_output`|stdout only|
|`redirect_error`|stderr only|
|`redirect_prefixed`|both streams, with line prefixes|

A stream with **no** file subscriber is relayed verbatim to the parent's corresponding stream — pipe, file, or terminal alike. The wrapper never silently discards child output; discarding a stream is data loss, not a default.

Two routes that resolve to the same file are refused before anything is opened. Resolution is by filesystem identity — device and inode for an existing file, resolved parent plus file name for one that does not exist yet, with dangling symlinks followed to their ultimate target — because two routes opened independently with truncation and written concurrently would interleave and overwrite each other's bytes without any I/O call failing. This is a package-local preflight guard against configuration mistakes; it does not close a time-of-check/time-of-use window, and it is not a filesystem security claim.

## Quickstart · `sec:execwrap:quickstart`

Validate a configuration, then run a child and route its streams:

```rust,no_run
// Spawns a real child process and writes log files, so this compiles
// but is not run as a doctest.
use std::ffi::OsString;

use execwrap::{Notification, RoutingConfig, preflight_routing, run};

fn main() -> Result<(), execwrap::ExecError> {
    let config = RoutingConfig {
        redirect_output: Some("build/tool-stdout.log".into()),
        redirect_error: Some("build/tool-stderr.log".into()),
        notify_on_write: true,
        ..RoutingConfig::default()
    };

    // Refuses an ambiguous routing configuration before any file is
    // opened, created, or truncated.
    preflight_routing(&config)?;

    let command: Vec<OsString> = vec!["echo".into(), "hello".into()];
    let outcome = run(&command, &config, |notification| match notification {
        Notification::WritingToLog { path, stream } => {
            println!("writing {} to {}", stream.label(), path.display());
        }
        Notification::WroteToLog { path } => {
            println!("wrote {}", path.display());
        }
    })?;

    // Losing captured output is a failure even when the child succeeded.
    if outcome.data_loss {
        return Err(execwrap::ExecError::EmptyCommand);
    }
    println!("child exited {}", outcome.exit_code);
    Ok(())
}
```

Preflight alone needs no child process, so it can be exercised directly:

```rust
use execwrap::{RoutingConfig, Stream, preflight_routing};

let config = RoutingConfig {
    redirect_output: Some("build/out.log".into()),
    ..RoutingConfig::default()
};

assert!(config.is_stream_redirected(Stream::Stdout));
assert!(!config.is_stream_redirected(Stream::Stderr));
preflight_routing(&config).expect("a single target is unambiguous");
```

## Public API tour · `sec:execwrap:public-api-tour`

### Root module · `sec:execwrap:root-module`

- `struct RoutingConfig { redirect, redirect_output, redirect_error, redirect_prefixed, notify_on_write, debug, quiet }` — all four targets are `Option<PathBuf>`; the rest are `bool`. `Default` gives no redirection at all, meaning both streams pass through to the parent.
- `RoutingConfig::is_stream_redirected(&self, stream: Stream) -> bool` — true when that stream has a file subscriber.
- `enum Stream { Stdout, Stderr }` — `label(self) -> &'static str` yields the uppercase name used in diagnostics.
- `preflight_routing(cfg: &RoutingConfig) -> Result<(), ExecError>` — stat-only validation. Returns `ExecError::AmbiguousRedirection` when one file is configured for multiple routing kinds.
- `run(command: &[OsString], cfg: &RoutingConfig, notify: impl FnMut(&Notification)) -> Result<ExecOutcome, ExecError>` — spawn, capture both pipes on reader threads, fan the bytes out to every subscribed writer, relay unsubscribed streams to the parent, and wait. `notify` is called only when `notify_on_write` is set.
- `struct ExecOutcome { exit_code: i32, data_loss: bool }` — a signal termination is reported as `128 + signal`. `data_loss` is true when a log write, a child-stream read, a reader thread, a parent flush, or a writer finalization failed.
- `enum Notification { WritingToLog { path, stream }, WroteToLog { path } }` — the immediate and deferred forms of the write notice.
- `enum ExecError { Io, Spawn { source }, EmptyCommand, AmbiguousRedirection { path } }` — The observation context retains the full public command before spawn, including failed attempts.
- `safe_open(path: &Path) -> io::Result<File>` — open for writing, creating parent directories as needed.

### `writer` module · `sec:execwrap:writer-module`

- `struct Writer` — `Writer::new(file: impl Write + Send + 'static, add_prefix: bool, wrap_length: usize, props: StreamProps, debug: bool)`, `write(&mut self, stream: Stream, raw: &[u8]) -> io::Result<()>`, `finalize(&mut self) -> io::Result<()>`.
- `struct StreamProps { line1_prefix_stdout, wrap_prefix_stdout, line1_prefix_stderr, wrap_prefix_stderr }` — all `String`, used only in prefixed mode.

The writer has two modes, and the distinction is load-bearing:

- **raw mode** (`add_prefix = false`) writes the child's bytes **unchanged**: no text conversion, no control-byte replacement, no truncation. Raw redirection must be byte-exact.
- **prefixed mode** (`add_prefix = true`) is a text presentation. It buffers per stream, splits on newline bytes, converts each *complete* line lossily, replaces control bytes other than newline, tab, and carriage return with `?`, and re-wraps with the per-stream prefix. Sanitisation runs on complete lines, never on read chunks, so a multibyte code point split across two pipe reads survives intact and the output does not depend on operating-system chunk boundaries.

`finalize` flushes any partial buffered line before flushing the file; skipping it loses a trailing unterminated line.

## Command-line contract · `sec:execwrap:command-line-contract`

```text
execwrap [--redirect FILE] [--redirect-output FILE] [--redirect-error FILE]
         [--redirect-prefixed FILE] [--notify-on-write]
         [--change-directory DIR] [--debug] [--quiet] -- COMMAND [ARG]...
```

The `--` separator is required by the argument grammar. Diagnostics are JSON on stderr; an ambiguous routing configuration is a usage error (class 2) emitted before any side effect, and the conflicting path stays out of the record because it is an argument value.

Exit-code mapping keeps the reserved wrapper classes intact:

|Child status|Wrapper exit|Why|
|------------|------------|---|
|0|0|success|
|1 or 2|1|class 2 stays reserved for wrapper usage|
|3 to 255|relayed|includes `128 + signal`|

A run that succeeded but lost captured output exits 1: a build must not continue silently on truncated logs.

## Error handling · `sec:execwrap:error-handling`

`run` returns `ExecError` for setup failures only — pipe or file preparation (`Io`), an empty command vector (`EmptyCommand`), a spawn failure (`Spawn`), or ambiguous routing (`AmbiguousRedirection`). A non-zero child status is **not** an error; it arrives through `ExecOutcome::exit_code`.

Per-stream failures during the run do not abort it. A failed log write, read error, panicked reader thread, parent flush failure, or writer finalization error is logged through `tracing` and sets `ExecOutcome::data_loss`. Callers must treat a run with `data_loss` as failed even when the child exited 0.

## What this package deliberately does not do · `sec:execwrap:what-this-package-deliberately-does-not-do`

- **It does not confine the child.** No sandbox, no privilege drop, no environment scrubbing, no argument filtering. Choosing the executable is authorizing it.
- **It does not sanitise child output.** In raw routing the bytes are written exactly as produced. The lossy conversion in prefixed mode is a presentation choice for a human-readable log, not a safety measure.
- **It does not discard a stream.** A stream with no file subscriber is always relayed to the parent.
- **It does not infer secrets from text.** Child arguments and I/O are public content; secret integrations require their own typed acquisition and reviewed exposure boundaries.
- **It does not merge streams except where asked.** Only `redirect` and `redirect_prefixed` combine them.
- **It does not claim atomic or race-free logging.** The identity preflight catches configuration aliases; it does not survive a host replacing a path between the check and the open.
- **It does not decide freshness or emit build metadata.** It is a process wrapper, not a build step.

## Consumers · `sec:execwrap:consumers`

The wrapper is available to callers that explicitly select a child command; it uses cli-common for the command-line output contract (`[ROOT-rec:output:decision]`).

## Claim areas · `sec:execwrap:areas`

**Section (cli)** · `sec:execwrap:area-cli` If process-wrapper claims fail, child output can be lost or mixed, routing can truncate prior logs, raw arguments can leak, and wrapper statuses can conceal child or delivery failure.

**Amendment (Foundation observation evidence)** · `amend:observe:foundation-evidence` The scoped implemented portions of (`[ROOT-gate:observe:foundation]`) and (`[ROOT-gate:design:observability-foundation]`) have these premises: Four production packages on the declared host configuration, public fixed inputs, controlled clocks and local exporters; syntax coverage and source-bound semantic reviews are distinct, generic capabilities retain their declared representation limits, and no real collector or service is assumed. Their evidence is (`[CLICOMMON-claim:cli:accounting-survives-trace-filtering]`), (`[CLICOMMON-claim:cli:async-context-follows-polls-not-thread-lifetime]`), (`[CLICOMMON-claim:cli:dropped-futures-record-cancellation-without-a-result]`), (`[CLICOMMON-claim:cli:invalid-clock-cannot-change-outcome]`), (`[CLICOMMON-claim:cli:metering-preserves-inclusive-time-and-owned-work]`), (`[CLICOMMON-claim:cli:metric-series-are-declared-and-bounded]`), (`[CLICOMMON-claim:cli:observation-loss-is-nonbinding]`), (`[CLICOMMON-claim:cli:private-configuration-remains-owned-through-failure-and-drop]`), (`[CLICOMMON-claim:cli:provider-bridge-preserves-counts-and-secret-boundary]`), (`[CLICOMMON-claim:cli:recursive-observation-is-loss-not-recursion]`), (`[CLICOMMON-claim:cli:secret-carriers-protect-nested-errors]`), (`[CLICOMMON-claim:cli:terminal-accounting-distinguishes-incomplete-work]`), (`[CLICOMMON-claim:cli:utc-input-never-infers-a-zone]`), (`claim:cli:observation-preserves-child-results`), (`claim:cli:public-child-arguments-are-observed`), (`claim:cli:public-child-urls-are-observed`), (`claim:cli:raw-redirect-is-byte-exact`), (`[INTERCHANGE-claim:vectors:deep-debug-retains-public-structure]`), ``[ROOT-claim:discipline:coverage-exceptions-are-local-and-witnessed]``, ``[ROOT-claim:discipline:coverage-recognition-comes-from-rust-syntax]``, ``[ROOT-claim:discipline:four-observation-modes-preserve-command-results]``, ``[ROOT-claim:discipline:generated-entry-points-need-explicit-admission]``, ``[ROOT-claim:discipline:metric-names-have-one-declaration]``, ``[ROOT-claim:discipline:metric-units-and-attributes-are-declared]``, ``[ROOT-claim:discipline:operation-identity-matches-its-source]``, ``[ROOT-claim:discipline:operation-roster-cannot-retain-stale-items]``, ``[ROOT-claim:discipline:public-bodies-require-parsed-boundaries]``, ``[ROOT-claim:discipline:secret-carriers-reject-printable-traits]``, ``[ROOT-claim:discipline:semantic-review-is-bound-to-source]``. The gate joins all claim siblings to current-source results and refuses missing, stale or failed mechanical coverage. Success, refusal, error, cancellation and unwinding have distinct completion outcomes; asynchronous context follows polls, and process death has no promised completion. Disabled, enabled, trace-filtered sampled and controlled failing-export runs preserve deterministic output bytes and exit. Fixed metric dimensions bound cardinality, and rejected recursion, queue overflow and export failures are accounted losses. Reviewer-confirmed full recording and secret-flow admission remain separate from syntactic proof. The present foundation instrumentation and comparison portion is supported; Real PostgreSQL and Elements service evidence: service implementer, provisioning slice; domain suites: assigned domain implementer, corresponding domain bite; client harnesses and actual exporter transport admission: client implementer, client slice. Decision-level evidence is not implicitly closed by these scoped gate rows.
