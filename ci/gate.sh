#!/usr/bin/env bash
# Run every foundation check and report one final verdict.
set -u
if [ "${1:-}" = --gate-storage-locked ]; then
    python3 -B ci/isolation.py storage-entry || exit 5
    shift
elif [ "${1:-}" != --gate-target-locked ]; then
    exec python3 -B ci/isolation.py gate-storage bash "$0" --gate-storage-locked "$@"
fi
if [ "${1:-}" = --gate-target-locked ]; then
    python3 -B ci/isolation.py locked-entry || exit 2
    python3 -B ci/isolation.py storage-entry || exit 5
    unset PN_GATE_LOCK_FD PN_GATE_LOCK_TOKEN
else
    python3 -B ci/build_graph.py declare || exit 2
fi
if [ -z "${TMPDIR:-}" ] || [ ! -d "$TMPDIR" ]; then
    echo "GATE-STRUCTURAL-ERROR: TMPDIR must name an existing caller-provided temporary directory" >&2
    exit 2
fi
if [ -z "${LINTER_BIN:-}" ] || [ ! -x "$LINTER_BIN" ]; then
    echo "GATE-STRUCTURAL-ERROR: LINTER_BIN must name an executable caller-provided linter" >&2
    exit 2
fi
if [ -z "${PN_POSTGRESQL_BIN:-}" ]; then
    echo "GATE-STRUCTURAL-ERROR: PN_POSTGRESQL_BIN must name the PostgreSQL binary directory" >&2
    exit 2
fi
if [ -z "${PN_ELEMENTS_BIN:-}" ]; then
    echo "GATE-STRUCTURAL-ERROR: PN_ELEMENTS_BIN must name the Elements binary directory" >&2
    exit 2
fi
if [ -z "${PN_MESON_BIN:-}" ]; then
    echo "GATE-STRUCTURAL-ERROR: PN_MESON_BIN must name the Meson executable" >&2
    exit 2
fi
case "${PN_BUILDGRAPH_ROUTE:-meson}" in
    meson|legacy) ;;
    *) echo "GATE-STRUCTURAL-ERROR: unknown build graph route" >&2; exit 2 ;;
esac
# The supervisor owns the lock through EXIT cleanup; children never inherit it.
if [ "${1:-}" = --gate-target-locked ]; then
    shift
else
    exec python3 -B ci/isolation.py gate-target bash "$0" --gate-target-locked "$@"
fi
failed=0
statuses=()
mkdir -p .lane
export PN_OBSERVE_ARTIFACT_DIR="$PWD/.lane/observations"
export PN_OBSERVE_LEVEL=default
export PN_HOST_TEST_ROOT="$PWD/.lane/host-postgres"
export PN_WALLET_TEST_ROOT="$PWD/.lane/wallet-elements"
trap 'python3 -B ci/wallet_elements.py stop-all --root "$PN_WALLET_TEST_ROOT"; python3 -B ci/host_postgresql.py stop --root "$PN_HOST_TEST_ROOT"' EXIT
# Signal cleanup waits for the adapter to terminate and reap its command tree.
active_pid=
gate_signal() {
    trap '' TERM INT
    local cleanup_status=0
    if [ -n "$active_pid" ]; then
        kill -s "$(($1 - 128))" "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || cleanup_status=$?
    fi
    if [ "$cleanup_status" -ne 0 ] && [ "$cleanup_status" -ne "$1" ]; then
        echo "GATE-CLEANUP-ERROR status=$cleanup_status requested=$1" >&2
        exit 2
    fi
    exit "$1"
}
trap 'gate_signal 143' TERM
trap 'gate_signal 130' INT
source ci/gate_resources.sh
resource_root=$(gate_cgroup_root 2>/dev/null) || resource_root=
quiet_window() {
    gate_resource_sample ".lane/gate-quiet-$1-start.raw" "$resource_root"
    sleep 5
    gate_resource_sample ".lane/gate-quiet-$1-end.raw" "$resource_root"
}
gate_started=$(date -u +%s.%N)
export PN_BUILDGRAPH_RUN="${gate_started}-$$"
python3 -B ci/build_graph.py instruction-probe || exit 2
python3 -B ci/build_graph.py series-receipt start || exit 4
gate_resource_sample .lane/gate-resource-start.raw "$resource_root" 2>/dev/null || true
times > .lane/gate-cpu-start.raw
quiet_window before
: > .lane/gate-steps.tsv
source_id=$(time git rev-parse HEAD)
export PN_GATE_SOURCE="$source_id"
python3 -B ci/build_graph.py bind-inputs || exit 2
if [ "${PN_IMPORT_BASE+x}" = x ]; then
    PN_IMPORT_BASE=$(python3 -B ci/isolation.py import-base) || exit 2
    export PN_IMPORT_BASE
fi
python3 -B ci/isolation.py retention || exit 2
export CARGO_NET_OFFLINE=true
unset PN_WALLET_CONFORMANCE_ISOLATED PN_HOST_RUNTIME_ISOLATED PN_CI_ISOLATED PN_GATE_BUILD_TARGET
rm -f .lane/ci-test_*-findings.jsonl .lane/performance-findings.jsonl .lane/performance-assessments.jsonl .lane/wallet-conformance-findings.jsonl .lane/host-observation-runtime-findings.jsonl .lane/over-budget-ledger.json .lane/performance-events.jsonl .lane/harness-ci-*.jsonl .lane/harness-matrix.json .lane/harness-benchmarks.jsonl .lane/observation-coverage.json .lane/observation-syntax.json
run_step() {
    local name=$1
    shift
    local status started ended wall
    local PN_GATE_STEP="$name" PN_GATE_SETUP_LOG="$PWD/.lane/gate-${name}-setup.jsonl" PN_GATE_SETUP_SOURCE="$source_id"
    export PN_GATE_STEP PN_GATE_SETUP_LOG PN_GATE_SETUP_SOURCE
    gate_resource_sample ".lane/gate-${name}-resource-start.raw" "$resource_root" 2>/dev/null || true
    started=$(date -u +%s.%N)
    if python3 -B ci/isolation.py bind-setup; then
    python3 -B ci/build_graph.py supervise bash -c 'TIMEFORMAT="OWN-TIME user=%U sys=%S"; time "$@"' gate-command "$@" > ".lane/gate-${name}.log" 2>&1 &
    active_pid=$!
    wait "$active_pid"
    status=$?
    active_pid=
    else
        status=2
        printf 'GATE-SETUP-REFUSED step=%s status=2\n' "$name" > ".lane/gate-${name}.log"
    fi
    ended=$(date -u +%s.%N)
    gate_resource_sample ".lane/gate-${name}-resource-end.raw" "$resource_root" 2>/dev/null || true
    wall=$(awk -v s="$started" -v e="$ended" 'BEGIN { printf "%.6f", e-s }')
    cat ".lane/gate-${name}.log"
    if [ "${PN_GATE_PARALLEL:-0}" = 1 ]; then
        printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$started" "$ended" > ".lane/completed-${name}.tsv"
    else
        printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$started" "$ended" >> .lane/gate-steps.tsv
    fi
    statuses+=("$name=$status/${wall}s")
    if [ "$status" -ne 0 ]; then failed=1; fi
    # Reporting has its own structural status; elapsed time never changes status.
    local budget=ordinary-check
    if [ "$name" = tests ]; then budget=test-command; fi
    if [ "$name" = reference-certificates ]; then budget=reference-gate; fi
    if [ "$name" = extended-tests ]; then budget=extended-gate; fi
    if [ "$name" = service-tests ]; then budget=service-gate; fi
    if [ "$name" = observation-runtime ]; then budget=pure-suite; fi
    case "$name" in
        hash-citations|build-graph|claim-tests|harness-tests|observation-tests|testkit-tests) budget="whole-tree-$name" ;;
        clippy|nursery-advisory|minimal|rustdoc|fixed-point-generate|fixed-point-write|datasets|documents|determinism-datasets|determinism-documents|cargo-config-measurement|discipline-tests|benchmarks|observation-syntax|observation-build|host-observation-build|observation-parser) budget=incremental-build ;;
    esac
    python3 -B ci/devperf.py --operation "$name" --duration-s "$wall" \
        --own-cpu-log ".lane/gate-${name}.log" \
        --outcome "exit:$status" --source "$source_id" --budget "$budget" \
        --findings .lane/performance-findings.jsonl
    if [ "$?" -ne 0 ]; then failed=1; fi
}
run_graph() {
    if [ "${PN_BUILDGRAPH_ROUTE:-meson}" = legacy ]; then
        run_step "$@"
    else
        local name=$1
        run_step "$name" python3 -B ci/build_graph.py delegate "$name"
    fi
}
# Meson owns the roster and dependencies; the shell retains resources and cleanup.
# A fixture without a parallel declaration retains the controlled serial route.
if python3 -B ci/build_graph.py parallel-declared; then
    export PN_GATE_PARALLEL=1
    export resource_root source_id
    export -f run_step run_graph gate_resource_sample gate_signal
    python3 -B ci/build_graph.py schedule &
    active_pid=$!
    wait "$active_pid" || failed=1
    active_pid=
else
    if python3 -B ci/build_graph.py plan > .lane/gate-plan.sh; then
        source .lane/gate-plan.sh
    else
        failed=1
    fi
fi
if ! python3 -B ci/build_graph.py finish; then failed=1; fi
grep 'Checking documents' .lane/gate-clippy.log || true
grep '^SUITE=' .lane/gate-tests.log || true
cat .lane/gate-toolchain.log
grep 'NURSERY-WITNESS-FINDINGS=' .lane/gate-discipline-tests.log || true
grep 'NURSERY-FINDINGS=' .lane/gate-nursery-advisory.log || true
if [ "${PN_GATE_PARALLEL:-0}" = 1 ]; then
    while IFS=$'\t' read -r name status started ended; do
        wall=$(awk -v s="$started" -v e="$ended" 'BEGIN { printf "%.6f", e-s }')
        statuses+=("$name=$status/${wall}s")
    done < .lane/gate-steps.tsv
fi
printf 'STEP-SUMMARY %s\n' "${statuses[*]}"
python3 -B ci/isolation.py target-sizes || failed=1
python3 ci/discipline.py diagnostics
quiet_window after
gate_ended=$(date -u +%s.%N)
gate_resource_sample .lane/gate-resource-end.raw "$resource_root" 2>/dev/null || true
times > .lane/gate-cpu-end.raw
gate_wall=$(awk -v s="$gate_started" -v e="$gate_ended" 'BEGIN { printf "%.6f", e-s }')
rm -f .lane/gate-resources.json
if python3 -B ci/gate_resources.py .lane "$gate_wall" > .lane/gate-resource-lines.log; then
    python3 -B ci/build_graph.py resource-lines .lane/gate-resource-lines.log
else
    while IFS=$'\t' read -r name status started ended; do
        printf 'STEP=%s STATUS=%s WALL=unavailable own_user_s=unavailable own_sys_s=unavailable cgroup_scope=unavailable node_scope=unavailable sampler=unavailable\n' "$name" "$status"
    done < .lane/gate-steps.tsv
    printf 'GATE-RESOURCES WALL=%ss own_user_s=unavailable own_sys_s=unavailable cgroup_scope=unavailable node_scope=unavailable sampler=unavailable\n' "$gate_wall"
fi
python3 -B ci/build_graph.py check-inputs || failed=1
python3 -B ci/build_graph.py wall-summary "$failed" "$gate_started" "$gate_ended" || failed=1
series_status=0
python3 -B ci/build_graph.py series-receipt end || series_status=4
python3 -B ci/devperf.py --ledger .lane --source "$source_id" || failed=1
if [ "$failed" = 0 ] && [ "${PN_GATE_PARALLEL:-0}" = 1 ]; then
    python3 -B ci/build_graph.py retain-baseline || failed=1
fi
printf 'GATE-EXIT=%s\n' "$failed"
if [ "$failed" = 0 ] && [ "$series_status" != 0 ]; then exit "$series_status"; fi
exit "$failed"
