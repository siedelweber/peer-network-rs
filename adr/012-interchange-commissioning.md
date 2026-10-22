**Record (Interchange commissioning)** · `rec:xchg:commissioning-record` Status: accepted. Scope: The pn-interchange commissioning and its implementation obligations. Depends on: (`rec:interchange:decision`). Does not establish: Implementation readiness establishes no external consumer or namespace allocation.

# The Interchange Crate — Commissioning · `rec:xchg:commissioning`

_Phase 4 of this four-record structure: commissioning. The point at which the crate is a workspace member other code may depend on, with its checks in the pipeline and its cost measured._

`pn-interchange` closed its feature surface at slice 4 and its audit in the third record. This note commissions it: it states what the crate is ready for, how it is checked, what it costs, and the two owner decisions that remain open against it.

## Readiness · `sec:xchg:commissioning-readiness`

The crate implements the interchange conventions end to end — the deterministic CBOR data language, the envelope, namespace labels, versions, the CDDL description language with the defined evaluable operator subset, satisfaction, the registry, and acceptance. The audit confirmed the canonical core sound under 6-million-input decode fuzzing and exhaustive half-precision-float checking, and its correctness findings are fixed. It is ready to be depended upon by a first consumer — a package carrying interchange documents. Consumer obligations remain those of (`sig:xchg:consumers`). A consumer should read the dispositions of two caveats: the memory-amplification disclosure (M3) and the parser DoS on hostile theory text (F1), both in [audit](011-interchange-audit.md).

No real consumer exists yet; the crate is commissioned as ready, not as consumed. When a package consumes it, that integration is the commissioning's confirmation, and any integration friction it surfaces returns here.

## Checks · `sec:xchg:commissioning-checks`

The crate is a workspace member, so `bash ci/gate.sh` covers formatting, Clippy under workspace lints, tests and documentation. Its test suite runs inside the gate’s `tests` step with a separately reported wall; the historical suite contained 668 tests. Fuzzing is outside the gate because it requires cargo-fuzz and has open-ended runtime: from `packages/interchange/fuzz`, run `bash seed.sh`, then `cargo +nightly fuzz run decode_canonical -- -max_total_time=60`, repeating for `cddl_parse` and `accept_document`. Run it at audit boundaries and before releases.

## Budget · `sec:xchg:commissioning-budget`

Measured 2026-08-21 in the original development environment (debug build): the full interchange test suite ran in **~5 s warm** (~15 s cold, the difference being doc-test compilation), of which the property lane was under a second. This historical figure remains comparison data. Measured 2026-10-22 by the repository's gate on its compute node: all 671 interchange tests, including doc tests, passed in **12.571484 s** inside the first green gate’s `tests` step using this checkout’s dedicated Cargo target (debug build; the initial gate includes test compilation). A regression in recurring test cost — a property case-count raised without notice, a new expensive test — is a finding, not a cost to absorb. The fuzz lane’s budget is its `-max_total_time` (60 s per target as run in the audit), set by the invoker.

## Open against the crate (owner decisions, non-blocking) · `sec:xchg:commissioning-open-against-the-crate-owner-decisions-non-blocking`

The following list preserves the commissioning-stage questions. The later close-out in [the audit](011-interchange-audit.md) records F1 as fixed by single-token lookahead and M3 as a documented linear memory bound; its remaining m3 alias-depth tradeoff stays visible there.

- **M3** — the ~48× memory amplification inherent to the no-nesting-bound policy: documented-as-is or capped, a change to (`dec:xchg:nesting-policy`).
- **F1** — the exponential-backtracking parser DoS: a reviewed refactor slice (lookahead instead of rewind-and-reparse).
- The **open-companion cut** change is implemented: a required-member cut remains a property of the member, not of the wildcard closure.

## Process note · `sec:xchg:commissioning-process-note`

The four records separate requirements, implementation decisions, adversarial findings and readiness evidence. Deferred design hazards remain explicit audit obligations, and the audit records reproductions and dispositions; the current repository gate verifies the checked implementation. No external workflow is required to interpret these records.
