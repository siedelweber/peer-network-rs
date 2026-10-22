#!/usr/bin/env bash
# Run every foundation check and report one final verdict.
set -u
failed=0
statuses=()
mkdir -p .lane
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
}
run_step toolchain python3 ci/discipline.py toolchain
run_step discipline-tests env FOUNDATION_COMPUTE_TESTS=1 python3 -B ci/test_discipline.py
run_step build-policy python3 ci/discipline.py build-policy
run_step cargo-config python3 ci/discipline.py cargo-config
run_step cargo-config-measurement python3 -B ci/measure_rustflags.py
run_step vendor-set python3 ci/discipline.py vendor-set
run_step member-lints python3 ci/discipline.py members
# Preserve the engine source layout; its only local edits are the documented scalar aliases.
run_step fmt python3 ci/discipline.py fmt
run_step clippy python3 ci/discipline.py clippy
run_step nursery-advisory python3 ci/discipline.py nursery
run_step tests python3 ci/discipline.py tests
# Discover first-party members for feature-minimal builds and documentation.
# Exclude regexml by name in discipline.py: it retains upstream feature and documentation policy.
run_step minimal python3 ci/discipline.py minimal
run_step rustdoc python3 ci/discipline.py rustdoc
run_step fixed-point-generate cargo run -p documents --locked -- generate
run_step fixed-point-write cargo run -p documents --locked -- write
run_step fixed-point-clean python3 ci/discipline.py tree-clean
run_step datasets cargo run -p documents --locked -- generate --check
run_step documents cargo run -p documents --locked -- check
run_step determinism-datasets cargo run -p documents --locked -- generate --check
run_step determinism-documents cargo run -p documents --locked -- check
run_step design-correspondence python3 -B ci/design.py
run_step design-tests python3 -B ci/test_design.py
run_step linter "${LINTER_BIN:-/workspace/loops/siedelweber/tools/bin/orchestration-linter}" check --root .
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
printf 'GATE-EXIT=%s\n' "$failed"
exit "$failed"
