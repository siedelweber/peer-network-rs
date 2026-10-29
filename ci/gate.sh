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
    if [ -n "$active_pid" ]; then
        kill -TERM "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || true
    fi
    exit "$1"
}
trap 'gate_signal 143' TERM
trap 'gate_signal 130' INT
gate_started=$(date -u +%s.%N)
export PN_BUILDGRAPH_RUN="${gate_started}-$$"
source ci/gate_resources.sh
resource_root=$(gate_cgroup_root 2>/dev/null) || resource_root=
gate_resource_sample .lane/gate-resource-start.raw "$resource_root" 2>/dev/null || true
times > .lane/gate-cpu-start.raw
: > .lane/gate-steps.tsv
source_id=$(time git rev-parse HEAD)
export CARGO_NET_OFFLINE=true
rm -f .lane/performance-events.jsonl .lane/harness-ci-*.jsonl .lane/harness-matrix.json .lane/harness-benchmarks.jsonl .lane/observation-coverage.json .lane/observation-syntax.json
run_step() {
    local name=$1
    shift
    local status started ended wall
    gate_resource_sample ".lane/gate-${name}-resource-start.raw" "$resource_root" 2>/dev/null || true
    started=$(date -u +%s.%N)
    python3 -B ci/build_graph.py supervise bash -c 'TIMEFORMAT="OWN-TIME user=%U sys=%S"; time "$@"' gate-command "$@" > ".lane/gate-${name}.log" 2>&1 &
    active_pid=$!
    wait "$active_pid"
    status=$?
    active_pid=
    ended=$(date -u +%s.%N)
    gate_resource_sample ".lane/gate-${name}-resource-end.raw" "$resource_root" 2>/dev/null || true
    wall=$(awk -v s="$started" -v e="$ended" 'BEGIN { printf "%.6f", e-s }')
    cat ".lane/gate-${name}.log"
    printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$started" "$ended" >> .lane/gate-steps.tsv
    statuses+=("$name=$status/${wall}s")
    if [ "$status" -ne 0 ]; then failed=1; fi
    # Reporting has its own structural status; elapsed time never changes status.
    local budget=ordinary-check
    if [ "$name" = tests ]; then budget=test-command; fi
    if [ "$name" = observation-runtime ]; then budget=pure-suite; fi
    case "$name" in
        clippy|nursery-advisory|minimal|rustdoc|fixed-point-generate|fixed-point-write|datasets|documents|determinism-datasets|determinism-documents|cargo-config-measurement|discipline-tests|benchmarks|observation-syntax|observation-build|host-observation-build|observation-parser) budget=incremental-build ;;
    esac
    python3 -B ci/devperf.py --operation "$name" --duration-s "$wall" \
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
# Meson owns the serial roster; the shell retains resources and unconditional cleanup.
if python3 -B ci/build_graph.py plan > .lane/gate-plan.sh; then
    source .lane/gate-plan.sh
else
    failed=1
fi
if ! python3 -B ci/build_graph.py finish; then failed=1; fi
grep 'Checking documents' .lane/gate-clippy.log || true
grep '^SUITE=' .lane/gate-tests.log || true
cat .lane/gate-toolchain.log
grep 'NURSERY-WITNESS-FINDINGS=' .lane/gate-discipline-tests.log || true
grep 'NURSERY-FINDINGS=' .lane/gate-nursery-advisory.log || true
printf 'STEP-SUMMARY %s\n' "${statuses[*]}"
python3 ci/discipline.py diagnostics
gate_ended=$(date -u +%s.%N)
gate_resource_sample .lane/gate-resource-end.raw "$resource_root" 2>/dev/null || true
times > .lane/gate-cpu-end.raw
gate_wall=$(awk -v s="$gate_started" -v e="$gate_ended" 'BEGIN { printf "%.6f", e-s }')
if python3 -B ci/gate_resources.py .lane "$gate_wall" > .lane/gate-resource-lines.log; then
    python3 -B ci/build_graph.py resource-lines .lane/gate-resource-lines.log
else
    while IFS=$'\t' read -r name status started ended; do
        printf 'STEP=%s STATUS=%s WALL=unavailable own_user_s=unavailable own_sys_s=unavailable node_load=unavailable sampler=unavailable\n' "$name" "$status"
    done < .lane/gate-steps.tsv
    printf 'GATE-RESOURCES WALL=%ss own_user_s=unavailable own_sys_s=unavailable node_load=unavailable sampler=unavailable\n' "$gate_wall"
fi
python3 -B ci/devperf.py --operation gate --duration-s "$gate_wall" --outcome "exit:$failed" \
    --source "$source_id" --budget gate --findings .lane/performance-findings.jsonl
if [ "$?" -ne 0 ]; then failed=1; fi
printf 'GATE-EXIT=%s\n' "$failed"
exit "$failed"
