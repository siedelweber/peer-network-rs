#!/usr/bin/env bash
# Run every foundation check and report one final verdict.
set -u
if [ -z "${TMPDIR:-}" ] || [ ! -d "$TMPDIR" ]; then
    echo "GATE-STRUCTURAL-ERROR: TMPDIR must name an existing caller-provided temporary directory" >&2
    exit 2
fi
if [ -z "${LINTER_BIN:-}" ] || [ ! -x "$LINTER_BIN" ]; then
    echo "GATE-STRUCTURAL-ERROR: LINTER_BIN must name an executable caller-provided linter" >&2
    exit 2
fi
failed=0
statuses=()
mkdir -p .lane
gate_started=$(date -u +%s.%N)
source_id=$(time git rev-parse HEAD)
export CARGO_NET_OFFLINE=true
rm -f .lane/performance-events.jsonl .lane/harness-ci-*.jsonl .lane/harness-matrix.json .lane/harness-benchmarks.jsonl
run_step() {
    local name=$1
    shift
    local status started ended wall
    started=$(date -u +%s.%N)
    { time "$@"; } > ".lane/gate-${name}.log" 2>&1
    status=$?
    ended=$(date -u +%s.%N)
    wall=$(awk -v s="$started" -v e="$ended" 'BEGIN { printf "%.6f", e-s }')
    cat ".lane/gate-${name}.log"
    printf 'STEP=%s STATUS=%s WALL=%ss\n' "$name" "$status" "$wall"
    statuses+=("$name=$status/${wall}s")
    if [ "$status" -ne 0 ]; then failed=1; fi
    # Reporting has its own structural status; elapsed time never changes status.
    local budget=ordinary-check
    if [ "$name" = tests ]; then budget=test-command; fi
    case "$name" in
        clippy|nursery-advisory|minimal|rustdoc|fixed-point-generate|fixed-point-write|datasets|documents|determinism-datasets|determinism-documents|cargo-config-measurement|discipline-tests|benchmarks) budget=incremental-build ;;
    esac
    python3 -B ci/devperf.py --operation "$name" --duration-s "$wall" \
        --outcome "exit:$status" --source "$source_id" --budget "$budget" \
        --findings .lane/performance-findings.jsonl
    if [ "$?" -ne 0 ]; then failed=1; fi
}
run_step toolchain python3 ci/discipline.py toolchain
run_step discipline-tests env FOUNDATION_COMPUTE_TESTS=1 python3 -B ci/run_ci.py test_discipline
run_step harness-registry python3 -B ci/harness.py
run_step harness-tests python3 -B ci/run_ci.py test_harness
run_step testkit-guard python3 -B ci/testkit_guard.py
run_step testkit-tests python3 -B ci/run_ci.py test_testkit
run_step claim-tests python3 -B ci/run_ci.py test_claims
run_step devperf-tests python3 -B ci/run_ci.py test_devperf
run_step build-policy python3 ci/discipline.py build-policy
run_step cargo-config python3 ci/discipline.py cargo-config
run_step cargo-config-measurement python3 -B ci/measure_rustflags.py
run_step vendor-set python3 ci/discipline.py vendor-set
run_step member-lints python3 ci/discipline.py members
# Preserve the engine source layout; README rule:vendor:regexml records the local aliases and XSD repetition correction.
run_step fmt python3 ci/discipline.py fmt
run_step clippy python3 ci/discipline.py clippy
run_step nursery-advisory python3 ci/discipline.py nursery
run_step tests python3 -B ci/discipline.py tests
run_step test-budgets python3 -B ci/devperf.py --input .lane/performance-events.jsonl --findings .lane/performance-findings.jsonl
# Discover first-party members for feature-minimal builds and documentation.
# Exclude regexml by name in discipline.py: it retains upstream feature and documentation policy.
run_step minimal python3 ci/discipline.py minimal
run_step rustdoc python3 ci/discipline.py rustdoc
run_step fixed-point-generate cargo run -p documents --locked --profile gate -- generate
run_step fixed-point-write cargo run -p documents --locked --profile gate -- write
run_step fixed-point-clean python3 ci/discipline.py tree-clean
run_step datasets cargo run -p documents --locked --profile gate -- generate --check
run_step documents cargo run -p documents --locked --profile gate -- check
run_step determinism-datasets cargo run -p documents --locked --profile gate -- generate --check
run_step determinism-documents cargo run -p documents --locked --profile gate -- check
run_step design-correspondence python3 -B ci/design.py
run_step design-tests python3 -B ci/run_ci.py test_design
run_step benchmarks python3 -B ci/benchmarks.py
run_step harness-matrix python3 -B ci/harness.py --matrix
run_step linter "$LINTER_BIN" check --root .
run_step claim-evidence python3 -B ci/claims.py --fail-respellings
run_step token python3 ci/discipline.py token
run_step hash-citations python3 -B ci/discipline.py hash-citations
run_step suppressions python3 ci/discipline.py suppressions
run_step printing python3 ci/discipline.py printing
grep 'Checking documents' .lane/gate-clippy.log || true
grep '^SUITE=' .lane/gate-tests.log || true
cat .lane/gate-toolchain.log
grep 'NURSERY-WITNESS-FINDINGS=' .lane/gate-discipline-tests.log || true
grep 'NURSERY-FINDINGS=' .lane/gate-nursery-advisory.log || true
printf 'STEP-SUMMARY %s\n' "${statuses[*]}"
python3 ci/discipline.py diagnostics
gate_ended=$(date -u +%s.%N)
gate_wall=$(awk -v s="$gate_started" -v e="$gate_ended" 'BEGIN { printf "%.6f", e-s }')
python3 -B ci/devperf.py --operation gate --duration-s "$gate_wall" --outcome "exit:$failed" \
    --source "$source_id" --budget gate --findings .lane/performance-findings.jsonl
if [ "$?" -ne 0 ]; then failed=1; fi
printf 'GATE-EXIT=%s\n' "$failed"
exit "$failed"
