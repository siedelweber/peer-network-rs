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
         [--change-directory DIR] [--debug] -- COMMAND [ARG]...
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

**Amendment (Foundation observation evidence)** · `amend:observe:foundation-operation-evidence` The scoped implemented portions of (`[ROOT-gate:observe:foundation]`) and (`[ROOT-gate:design:observability-foundation]`) have these premises: Four production packages on the declared host configuration, public fixed inputs, controlled clocks and local exporters; syntax coverage and source-bound semantic reviews are distinct, generic capabilities retain their declared representation limits, and no real collector or service is assumed. Their evidence is (`[CLICOMMON-claim:cli:artifact-root-is-fixed-before-directory-change]`), (`[CLICOMMON-claim:cli:default-emission-retains-problems-and-cost]`), (`[CLICOMMON-claim:cli:custom-debug-errors-remain-errors]`), (`[CLICOMMON-claim:cli:all-bootstrap-routes-preserve-configuration-refusal]`), (`[CLICOMMON-claim:cli:large-content-is-addressed-once]`), (`[CLICOMMON-claim:cli:public-content-encoding-is-lossless]`), (`[CLICOMMON-claim:cli:accounting-survives-trace-filtering]`), (`[CLICOMMON-claim:cli:async-context-follows-polls-not-thread-lifetime]`), (`[CLICOMMON-claim:cli:dropped-futures-record-cancellation-without-a-result]`), (`[CLICOMMON-claim:cli:invalid-clock-cannot-change-outcome]`), (`[CLICOMMON-claim:cli:metering-preserves-inclusive-time-and-owned-work]`), (`[CLICOMMON-claim:cli:metric-series-are-declared-and-bounded]`), (`[CLICOMMON-claim:cli:observation-loss-is-nonbinding]`), (`[CLICOMMON-claim:cli:private-configuration-remains-owned-through-failure-and-drop]`), (`[CLICOMMON-claim:cli:provider-bridge-preserves-counts-and-secret-boundary]`), (`[CLICOMMON-claim:cli:recursive-observation-is-loss-not-recursion]`), (`[CLICOMMON-claim:cli:secret-carriers-protect-nested-errors]`), (`[CLICOMMON-claim:cli:terminal-accounting-distinguishes-incomplete-work]`), (`[CLICOMMON-claim:cli:utc-input-never-infers-a-zone]`), (`claim:cli:observation-preserves-child-results`), (`claim:cli:public-child-arguments-are-observed`), (`claim:cli:public-child-urls-are-observed`), (`claim:cli:raw-redirect-is-byte-exact`), (`[INTERCHANGE-claim:vectors:deep-debug-retains-public-structure]`), (`[ROOT-claim:discipline:coverage-exceptions-are-local-and-witnessed]`), (`[ROOT-claim:discipline:coverage-recognition-comes-from-rust-syntax]`), (`[ROOT-claim:discipline:four-observation-modes-preserve-command-results]`), (`[ROOT-claim:discipline:generated-entry-points-need-explicit-admission]`), (`[ROOT-claim:discipline:metric-names-have-one-declaration]`), (`[ROOT-claim:discipline:metric-units-and-attributes-are-declared]`), (`[ROOT-claim:discipline:operation-identity-matches-its-source]`), (`[ROOT-claim:discipline:operation-roster-cannot-retain-stale-items]`), (`[ROOT-claim:discipline:public-bodies-require-parsed-boundaries]`), (`[ROOT-claim:discipline:secret-carriers-reject-printable-traits]`), (`[ROOT-claim:discipline:semantic-review-is-bound-to-source]`). The gate joins all claim siblings to current-source results and refuses missing, stale or failed mechanical coverage. Success, refusal, error, cancellation and unwinding have distinct completion outcomes; asynchronous context follows polls, and process death has no promised completion. Disabled, default, full trace and controlled failing-export (full trace) runs preserve deterministic output bytes and exit. Fixed metric dimensions bound cardinality, and rejected recursion, queue overflow and export failures are accounted losses. Reviewer-confirmed full recording and secret-flow admission remain separate from syntactic proof. The present foundation instrumentation and comparison portion is supported; Real PostgreSQL and Elements service evidence: service implementer, provisioning slice; domain suites: assigned domain implementer, corresponding domain bite; client harnesses and actual exporter transport admission: client implementer, client slice. Decision-level evidence is not implicitly closed by these scoped gate rows.

**Amendment (Evidence hosting)** · `amend:observe:evidence-hosting` The foundation observation paragraph (`amend:observe:foundation-operation-evidence`) lives here because execwrap hosts the four-package process comparison and repository policy cannot import package-owned claim heads. EXECWRAP has INTERCHANGE and DOCUMENTS reach for this evidence and composition; ROOT has no TESTKIT reach. The ROOT scope paragraph retains its distinct local label; neither paragraph claims evidence outside its declared premises.

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-devperf-feedback` For (`[ROOT-dec:devperf:feedback]`), Controlled passing and failing executions retain their outcomes under excess durations; budget categories distinguish performance evidence from structural configuration. This supports the current reporter, not a latency promise. Evidence: (`[ROOT-claim:devperf:timing-preserves-predicates]`), (`[ROOT-claim:devperf:category-controls-classification]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-devperf-profiles` For (`[ROOT-dec:devperf:profiles]`), The current workspace profile retains assertions and overflow checks and the guard refuses drift. The accepted cold/warm comparison samples and profile decision remain recorded in records 013 and 021; this witness checks continued configuration, not a new measurement campaign. Evidence: (`[ROOT-claim:devperf:gate-profile-guards]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-harness-levels` For (`[ROOT-dec:harness:levels]`), The complete current roster declares every case and level; controlled omissions refuse structurally. The public-surface layout amendment bounds the present package witnesses; future packages require their own levels. Evidence: (`[ROOT-claim:harness:missing-level-refused]`), (`[ROOT-claim:harness:dropped-case-refused]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-labels-policy` For (`[ROOT-dec:labels:policy]`), The current adoption inputs and rendered owner declarations are one checked fixed point, and the deployed linter checks the actual current corpus without warnings. This is adoption and corpus resolution evidence, not a proof of all linter algorithms. Evidence: (`[DOCUMENTS-claim:render:paired-census]`), (`[DOCUMENTS-claim:render:declaration-authority]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-lint-policy` For (`[ROOT-dec:lint:policy]`), Manifest inheritance, forbidden configuration relaxation and test-tree suppressions have negative fixtures; the current gate supplies formatting, required Clippy and the separate advisory pass. Vendor policy remains the documented exception. Evidence: (`[ROOT-claim:discipline:members-inherit-workspace-lints]`), (`[ROOT-claim:discipline:test-lints-cannot-be-suppressed]`), (`[ROOT-claim:discipline:configuration-cannot-relax-lints]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-observe-foundation` For (`[ROOT-dec:observe:foundation]`), The source-bound production operation census and negative fixtures establish mechanical admission; body-bound class decisions remain semantic reviews. Current local execution and export witnesses do not admit a network service. Evidence: (`[ROOT-claim:discipline:public-bodies-require-parsed-boundaries]`), (`[ROOT-claim:discipline:semantic-review-is-bound-to-source]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-observe-secrets` For (`[ROOT-dec:observe:secrets]`), Compile-fail probes reject Display and accidental serde serialization for the current protected carriers. Acquisition and future explicit exposure consumers remain governed by their separate admission boundary. Evidence: (`[ROOT-claim:discipline:secret-carriers-reject-printable-traits]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-observe-sinks` For (`[ROOT-dec:observe:sinks]`), Current executable-owned JSON delivery, queue saturation and recursive-entry fixtures preserve binding results and reserve summary capacity. Real service export and service configuration are outside this scope. Evidence: (`[CLICOMMON-claim:cli:observation-loss-is-nonbinding]`), (`[CLICOMMON-claim:cli:recursive-observation-is-loss-not-recursion]`), (`[CLICOMMON-claim:cli:summary-capacity-survives-ordinary-saturation]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-output-policy` For (`[ROOT-dec:output:policy]`), Subprocess witnesses cover help, version, usage, terminal refusal, clean output, findings, runtime errors and public panic diagnostics. Observation adds JSON stderr records while preserving stdout and exit; clean results forbid WARN and ERROR records. Evidence: (`[DOCUMENTS-claim:cli:control-records]`), (`[DOCUMENTS-claim:cli:terminal-refusal]`), (`[DOCUMENTS-claim:cli:clean-result]`), (`[DOCUMENTS-claim:cli:finding-status]`), (`[DOCUMENTS-claim:cli:runtime-error]`), (`[DOCUMENTS-claim:cli:panic-proxy]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-render-policy` For (`[ROOT-dec:render:policy]`), The actual repository and controlled fixtures establish deterministic projections, rendering, protected outputs, JSON envelopes and tracked-path census. The engine-generated bytes are checked as a clean fixed point. Evidence: (`[DOCUMENTS-claim:render:repository-fixed-point]`), (`[DOCUMENTS-claim:render:dataset-mutation]`), (`[DOCUMENTS-claim:render:stale-rendering]`), (`[DOCUMENTS-claim:render:protected-outputs]`), (`[DOCUMENTS-claim:envelope:json-model]`), (`[DOCUMENTS-claim:render:tracked-census]`), (`[DOCUMENTS-claim:render:git-required]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-testing-evidence` For (`[ROOT-dec:testing:evidence]`), The current checked carriers and source-matched runner results support scoped obligations only through resolving evidence edges; a failed sibling dominates. Meaning is the reviewed gloss premise, not a passing count. Evidence: (`[ROOT-claim:testing:sibling-failure-dominates]`), (`[ROOT-claim:testing:python-edges-require-known-claims]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-toolchain-compiler` For (`[ROOT-dec:toolchain:compiler]`), The gate logs the answering compiler and tools, checks undated nightly and forbids unsupported minimum versions; required release settings and the separately measured gate profile are checked. This supports the current declared toolchain, not compiler-version reproducibility. Evidence: (`[ROOT-claim:discipline:toolchain-family-is-consistent]`), (`[ROOT-claim:devperf:gate-profile-guards]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-toolchain-minimum` For (`[ROOT-dec:toolchain:minimum]`), The gate logs the answering compiler and tools, checks undated nightly and forbids unsupported minimum versions; required release settings and the separately measured gate profile are checked. This supports the current declared toolchain, not compiler-version reproducibility. Evidence: (`[ROOT-claim:discipline:toolchain-family-is-consistent]`), (`[ROOT-claim:devperf:gate-profile-guards]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-toolchain-release` For (`[ROOT-dec:toolchain:release]`), The gate logs the answering compiler and tools, checks undated nightly and forbids unsupported minimum versions; required release settings and the separately measured gate profile are checked. This supports the current declared toolchain, not compiler-version reproducibility. Evidence: (`[ROOT-claim:discipline:toolchain-family-is-consistent]`), (`[ROOT-claim:devperf:gate-profile-guards]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-cddl-coverage` For (`[ROOT-dec:xchg:cddl-coverage]`), The committed grammar corpus and operator fixtures cover parsing and the documented evaluation subset. This is the current corpus witness, not a proof over every grammar derivation. Evidence: (`[INTERCHANGE-claim:parse:the-standards-corpus-parses]`), (`[INTERCHANGE-claim:cddl:every-operator-of-the-subset-is-admitted]`), (`[INTERCHANGE-claim:cddl:an-unevaluable-operator-is-refused-wherever-it-stands]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-crate-layout` For (`[ROOT-dec:xchg:crate-layout]`), The checked crate root has no `no_std` attribute and the manifest declares one library, no feature matrix or binary, and only the accepted production dependencies. The source-bound Value declaration remains exhaustive. Test-only corpus/benchmark dependencies do not enter that production graph. Evidence: (`[ROOT-claim:harness:interchange-structure-is-declared]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-evaluable-subset` For (`[ROOT-dec:xchg:evaluable-subset]`), Each supported operator is admitted and the unsupported operators are refused at their actual sites; no unsupported operator is approximated. Evidence: (`[INTERCHANGE-claim:cddl:every-operator-of-the-subset-is-admitted]`), (`[INTERCHANGE-claim:cddl:an-unevaluable-operator-is-refused-wherever-it-stands]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-float-bits` For (`[ROOT-dec:xchg:float-bits]`), Canonical float fixtures pin accepted widths and NaN refusals; sampled bit patterns are compared to the independent width oracle. The bounded corpus and recorded property cases support the present implementation. Evidence: (`[INTERCHANGE-claim:encoding:a-float-stands-in-its-shortest-form]`), (`[INTERCHANGE-claim:properties:sampled-floats-use-the-independent-minimal-width]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-nan-policy` For (`[ROOT-dec:xchg:nan-policy]`), Acquisition fixtures refuse noncanonical NaN payloads and the negative sign with `NonCanonicalFloat`; canonical float fixtures pin accepted widths and decoder refusals; sampled bit patterns are compared to the independent width oracle. The bounded corpus and recorded property cases support the present implementation. Evidence: (`[INTERCHANGE-claim:encoding:float-acquisition-refuses-noncanonical-nans]`), (`[INTERCHANGE-claim:encoding:a-float-stands-in-its-shortest-form]`), (`[INTERCHANGE-claim:properties:sampled-floats-use-the-independent-minimal-width]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-nesting-policy` For (`[ROOT-dec:xchg:nesting-policy]`), Deep canonical decode/encode and derived value walks, including teardown, execute with explicit work stacks. These concrete depth witnesses do not claim an unbounded machine resource supply. Evidence: (`[INTERCHANGE-claim:properties:the-deep-paths-are-iterative]`), (`[INTERCHANGE-claim:properties:the-derived-walks-are-iterative-too]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-prefix-public` For (`[ROOT-dec:xchg:prefix-public]`), An external public consumer distinguishes consumed prefix extent from strict whole-input decoding; generated envelopes preserve routing within the declared prefix bound. Evidence: (`[INTERCHANGE-claim:vectors:public-prefix-extent]`), (`[INTERCHANGE-claim:properties:generated-prefix-dispatch-preserves-envelope-routing]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-public-printer` For (`[ROOT-dec:xchg:public-printer]`), The externally exercised printer normalizes layout while the type-identity witness distinguishes spelling from structural identity; the current public surface remains callable by consumers. Evidence: (`[INTERCHANGE-claim:inclusion:identity-of-type-is-the-printers-question]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-refused-dependencies` For (`[ROOT-dec:xchg:refused-dependencies]`), The checked crate root has no `no_std` attribute and the manifest declares one library, no feature matrix or binary, and only the accepted production dependencies. The source-bound Value declaration remains exhaustive. Test-only corpus/benchmark dependencies do not enter that production graph. Evidence: (`[ROOT-claim:harness:interchange-structure-is-declared]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-regexp-engine` For (`[ROOT-dec:xchg:regexp-engine]`), The seam uses whole-subject XSD matching and a deterministic operations budget; an independent automaton checks declared subset membership, including nullable repetition. Current fork corrections and the pathological split are recorded in the regexp provenance and interchange documentation; no linear-time claim is made. Evidence: (`[INTERCHANGE-claim:regexp:a-pattern-matches-the-whole-subject]`), (`[INTERCHANGE-claim:regexp:the-budget-bounds-every-walk]`), (`[INTERCHANGE-claim:regexp:the-oracle-agrees-with-language-facts]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-regexp-seam` For (`[ROOT-dec:xchg:regexp-seam]`), The seam uses whole-subject XSD matching and a deterministic operations budget; an independent automaton checks declared subset membership, including nullable repetition. Current fork corrections and the pathological split are recorded in the regexp provenance and interchange documentation; no linear-time claim is made. Evidence: (`[INTERCHANGE-claim:regexp:a-pattern-matches-the-whole-subject]`), (`[INTERCHANGE-claim:regexp:the-budget-bounds-every-walk]`), (`[INTERCHANGE-claim:regexp:the-oracle-agrees-with-language-facts]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-registry-loading` For (`[ROOT-dec:xchg:registry-loading]`), The public sequence acquisition witnesses retain an ascending chain and stop at the first named refusal, without inventing a different loading service. Evidence: (`[INTERCHANGE-claim:registry:acquire-all-stops-at-the-first-refusal]`), (`[INTERCHANGE-claim:registry:acquire-all-takes-a-whole-ascending-chain]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-restraint-enforcement` For (`[ROOT-dec:xchg:restraint-enforcement]`), Acquisition refuses undeclared restrained reaches; the explicit lenient option changes that check alone in the fixture. Evidence: (`[INTERCHANGE-claim:registry:an-implicit-reach-is-refused]`), (`[INTERCHANGE-claim:registry:leniency-relaxes-the-reach-alone]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-theory-sharing` For (`[ROOT-dec:xchg:theory-sharing]`), Registry reacquisition preserves the held theory and refuses a changed same identity. This witnesses immutable sharing at the current public registry boundary. Evidence: (`[INTERCHANGE-claim:registry:a-held-theory-is-immutable]`), (`[INTERCHANGE-claim:registry:re-acquiring-the-held-theory-changes-nothing]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-type-identity` For (`[ROOT-dec:xchg:type-identity]`), Expression printing and reached rule identities determine the checked type identity; equivalent layout alone cannot alter it. Evidence: (`[INTERCHANGE-claim:inclusion:identity-of-type-is-the-printers-question]`), (`[INTERCHANGE-claim:inclusion:an-identity-is-the-expression-and-the-rules-it-reaches]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-utf8-policy` For (`[ROOT-dec:xchg:utf8-policy]`), The canonical decoder refuses invalid UTF-8 at the named byte while valid text remains in the single string representation. Evidence: (`[INTERCHANGE-claim:encoding:a-text-string-must-be-valid-utf8]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-dec-xchg-value-exhaustive` For (`[ROOT-dec:xchg:value-exhaustive]`), The checked crate root has no `no_std` attribute and the manifest declares one library, no feature matrix or binary, and only the accepted production dependencies. The source-bound Value declaration remains exhaustive. Test-only corpus/benchmark dependencies do not enter that production graph. Evidence: (`[ROOT-claim:harness:interchange-structure-is-declared]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-foundation-verification` For (`[ROOT-gate:foundation:verification]`), The current source commit must finish every gate step with status zero; structural policy, evidence and observation checks are independently exercised. Duration warnings remain nonverdict outputs. Services and later domain evidence are not inferred. Evidence: (`[ROOT-claim:discipline:members-inherit-workspace-lints]`), (`[ROOT-claim:testing:sibling-failure-dominates]`), (`[ROOT-claim:discipline:public-bodies-require-parsed-boundaries]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-kinds-adoption` For (`[ROOT-gate:kinds:adoption]`), The accepted adoption data, relation/status fixtures and actual rendered register establish the current ordered register and its derived counts and homonyms. Evidence/status judgments are accepted input facts; the renderer does not invent them. Evidence: (`[DOCUMENTS-claim:render:registry-relation]`), (`[DOCUMENTS-claim:render:paired-census]`), (`[DOCUMENTS-claim:render:repository-fixed-point]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-labels-verification` For (`[ROOT-gate:labels:verification]`), The current adoption inputs and rendered owner declarations are one checked fixed point, and the deployed linter checks the actual current corpus without warnings. This is adoption and corpus resolution evidence, not a proof of all linter algorithms. Evidence: (`[DOCUMENTS-claim:render:paired-census]`), (`[DOCUMENTS-claim:render:declaration-authority]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-lint-verification` For (`[ROOT-gate:lint:verification]`), Manifest inheritance, forbidden configuration relaxation and test-tree suppressions have negative fixtures; the current gate supplies formatting, required Clippy and the separate advisory pass. Vendor policy remains the documented exception. Evidence: (`[ROOT-claim:discipline:members-inherit-workspace-lints]`), (`[ROOT-claim:discipline:test-lints-cannot-be-suppressed]`), (`[ROOT-claim:discipline:configuration-cannot-relax-lints]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-output-verification` For (`[ROOT-gate:output:verification]`), Subprocess witnesses cover help, version, usage, terminal refusal, clean output, findings, runtime errors and public panic diagnostics. Observation adds JSON stderr records while preserving stdout and exit; clean results forbid WARN and ERROR records. Evidence: (`[DOCUMENTS-claim:cli:control-records]`), (`[DOCUMENTS-claim:cli:terminal-refusal]`), (`[DOCUMENTS-claim:cli:clean-result]`), (`[DOCUMENTS-claim:cli:finding-status]`), (`[DOCUMENTS-claim:cli:runtime-error]`), (`[DOCUMENTS-claim:cli:panic-proxy]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-render-verification` For (`[ROOT-gate:render:verification]`), The actual repository and controlled fixtures establish deterministic projections, rendering, protected outputs, JSON envelopes and tracked-path census. The engine-generated bytes are checked as a clean fixed point. Evidence: (`[DOCUMENTS-claim:render:repository-fixed-point]`), (`[DOCUMENTS-claim:render:dataset-mutation]`), (`[DOCUMENTS-claim:render:stale-rendering]`), (`[DOCUMENTS-claim:render:protected-outputs]`), (`[DOCUMENTS-claim:envelope:json-model]`), (`[DOCUMENTS-claim:render:tracked-census]`), (`[DOCUMENTS-claim:render:git-required]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-gate-toolchain-verification` For (`[ROOT-gate:toolchain:verification]`), The gate logs the answering compiler and tools, checks undated nightly and forbids unsupported minimum versions; required release settings and the separately measured gate profile are checked. This supports the current declared toolchain, not compiler-version reproducibility. Evidence: (`[ROOT-claim:discipline:toolchain-family-is-consistent]`), (`[ROOT-claim:devperf:gate-profile-guards]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-req-kinds-attestation-register` For (`[ROOT-req:kinds:attestation-register]`), The accepted adoption data, relation/status fixtures and actual rendered register establish the current ordered register and its derived counts and homonyms. Evidence/status judgments are accepted input facts; the renderer does not invent them. Evidence: (`[DOCUMENTS-claim:render:registry-relation]`), (`[DOCUMENTS-claim:render:paired-census]`), (`[DOCUMENTS-claim:render:repository-fixed-point]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-req-xchg-determinism` For (`[ROOT-req:xchg:determinism]`), Bounded generated values round-trip uniquely and sampled byte strings are refused or retained byte for byte; the independent canonical vector corpus supplements those recorded property cases. Evidence: (`[INTERCHANGE-claim:properties:generated-values-have-unique-canonical-names]`), (`[INTERCHANGE-claim:properties:sampled-bytes-are-refused-or-preserved]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-req-xchg-regexp-guard` For (`[ROOT-req:xchg:regexp-guard]`), The seam uses whole-subject XSD matching and a deterministic operations budget; an independent automaton checks declared subset membership, including nullable repetition. Current fork corrections and the pathological split are recorded in the regexp provenance and interchange documentation; no linear-time claim is made. Evidence: (`[INTERCHANGE-claim:regexp:a-pattern-matches-the-whole-subject]`), (`[INTERCHANGE-claim:regexp:the-budget-bounds-every-walk]`), (`[INTERCHANGE-claim:regexp:the-oracle-agrees-with-language-facts]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-req-xchg-std-only` For (`[ROOT-req:xchg:std-only]`), The checked crate root has no `no_std` attribute and the manifest declares one library, no feature matrix or binary, and only the accepted production dependencies. The source-bound Value declaration remains exhaustive. Test-only corpus/benchmark dependencies do not enter that production graph. Evidence: (`[ROOT-claim:harness:interchange-structure-is-declared]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-req-xchg-timing` For (`[ROOT-req:xchg:timing]`), The joined result stream retains every current case duration, suite and implementation, separating property and vector suites and reporting excesses without changing predicates. Evidence: (`[ROOT-claim:devperf:timing-preserves-predicates]`), (`[ROOT-claim:devperf:result-accounting-is-explicit]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-req-xchg-workspace-discipline` For (`[ROOT-req:xchg:workspace-discipline]`), Current manifest inheritance, selected production dependencies and the complete gate establish repository discipline for the shared library; no alternate domain codec is admitted here. Evidence: (`[ROOT-claim:discipline:members-inherit-workspace-lints]`), (`[ROOT-claim:harness:interchange-structure-is-declared]`).

**Amendment (Scoped evidence admission)** · `amend:foundation:evidence-verif-xchg-label-pattern-crosscheck` For (`[ROOT-verif:xchg:label-pattern-crosscheck]`), The declared namespace pattern is compared with the hand-written label recognizer over the committed near-miss and generated subject corpus; the premise is the current declared pattern set. Evidence: (`[INTERCHANGE-claim:regexp:the-namespace-pattern-recognizes-labels]`).

**Amendment (Current requirement evidence)** · `amend:foundation:requirement-admissions` Implements (`[ROOT-verif:testing:foundation-admissions]`) for the current registered configuration, with the narrower premises of each requirement row. Evidence: (`[DOCUMENTS-claim:render:paired-census]`), (`[DOCUMENTS-claim:render:registry-relation]`), (`[DOCUMENTS-claim:render:repository-fixed-point]`), (`[INTERCHANGE-claim:properties:generated-values-have-unique-canonical-names]`), (`[INTERCHANGE-claim:properties:sampled-bytes-are-refused-or-preserved]`), (`[INTERCHANGE-claim:regexp:a-pattern-matches-the-whole-subject]`), (`[INTERCHANGE-claim:regexp:the-budget-bounds-every-walk]`), (`[INTERCHANGE-claim:regexp:the-oracle-agrees-with-language-facts]`), (`[ROOT-claim:devperf:result-accounting-is-explicit]`), (`[ROOT-claim:devperf:timing-preserves-predicates]`), (`[ROOT-claim:discipline:members-inherit-workspace-lints]`), (`[ROOT-claim:harness:interchange-structure-is-declared]`).
