#!/usr/bin/env bash
# Run the repository's direct, service-free checks with the selected compiler.
# Exit status: 0 green; 1 a tree check failed; 2 the entry refused before any step; 3 the tree is green and the environment failed.
set -u
TIMEFORMAT='%U %S'
cd "$(dirname "$0")/.." || exit 2

if [[ ${1:-} == --identity ]]; then
    rustc -vV
    a=$?
    cargo -V
    b=$?
    cargo clippy -V
    c=$?
    rustfmt -V
    d=$?
    exit $((a | b | c | d))
fi

if [[ ${1:-} == --compiler-age ]]; then
    commit_date=$(rustc -vV | sed -n 's/^commit-date: //p')
    if [[ ! $commit_date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        printf 'COMPILER-AGE refusal=missing-commit-date\n' >&2
        exit 2
    fi
    today=$(date -u +%F)
    today_day=$(date -u -d "$today" +%s) || { printf 'COMPILER-AGE refusal=utc-date-conversion\n' >&2; exit 2; }
    commit_day=$(date -u -d "$commit_date" +%s) || { printf 'COMPILER-AGE refusal=commit-date-conversion\n' >&2; exit 2; }
    age_days=$(((today_day - commit_day) / 86400))
    printf 'COMPILER-DATE=%s UTC-DATE=%s AGE-DAYS=%s\n' "$commit_date" "$today" "$age_days"
    if ((age_days < 0 || age_days > 2)); then exit 1; fi
    exit 0
fi

if [[ -z ${LINTER_BIN:-} ]]; then
    printf 'ENTRY-REFUSAL missing LINTER_BIN\n' >&2
    exit 2
fi
if [[ ! -x $LINTER_BIN ]]; then
    printf 'ENTRY-REFUSAL LINTER_BIN is not executable: %s\n' "$LINTER_BIN" >&2
    exit 2
fi

export RUSTC
RUSTC=$(command -v rustc)
export RUSTDOC
RUSTDOC=$(command -v rustdoc)
export CARGO_NET_OFFLINE=true

cg_path=$(awk -F: '$1 == "0" { print $3; found = 1 } END { if (!found) print "unavailable" }' /proc/self/cgroup 2>/dev/null)
cg_root="/sys/fs/cgroup${cg_path}"
cg_scope=${PN_CHECK_CGROUP_SCOPE:-unstated}
case $cg_scope in
    own | shared | unstated) ;;
    *) printf 'ENTRY-REFUSAL PN_CHECK_CGROUP_SCOPE is not own or shared: %s\n' "$cg_scope" >&2; exit 2 ;;
esac
cpu_sample() {
    if [[ ! -r $cg_root/cpu.stat ]]; then printf 'unavailable\n'; return; fi
    awk -v key="$1" '$1 == key { print $2; found = 1 } END { if (!found) print "unavailable" }' "$cg_root/cpu.stat" 2>/dev/null
}
mem_sample() {
    if [[ -r $cg_root/$1 ]]; then cat "$cg_root/$1"; else printf 'unavailable\n'; fi
}
pressure_sample() {
    local kind=$1 phase=$2 field=$3
    if [[ ! -r $cg_root/$kind.pressure ]]; then printf 'unavailable\n'; return; fi
    awk -v phase="$phase" -v field="$field" '$1 == phase { for (i = 2; i <= NF; i++) { split($i, pair, "="); if (pair[1] == field) { print pair[2]; found = 1; exit } } } END { if (!found) print "unavailable" }' "$cg_root/$kind.pressure"
}
delta() {
    if [[ $1 =~ ^[0-9]+$ && $2 =~ ^[0-9]+$ ]]; then printf '%s' "$(( $2 - $1 ))"; else printf 'unavailable'; fi
}
declare -A run_before run_after before after
sample_resources() {
    local -n sample=$1
    local key kind phase field
    for key in usage_usec user_usec system_usec nr_periods nr_throttled throttled_usec; do
        sample["$key"]=$(cpu_sample "$key")
    done
    sample[memory_current]=$(mem_sample memory.current)
    sample[memory_peak]=$(mem_sample memory.peak)
    for kind in cpu memory io; do
        for phase in some full; do
            for field in avg10 avg60 avg300 total; do
                key="${kind}_${phase}_${field}"
                sample["$key"]=$(pressure_sample "$kind" "$phase" "$field")
            done
        done
    done
}
print_resources() {
    local -n first=$1 last=$2
    local key
    printf ' CGROUP_PATH=%s CGROUP_SCOPE=%s' "$cg_path" "$cg_scope"
    for key in usage_usec user_usec system_usec nr_periods nr_throttled throttled_usec memory_current; do
        printf ' %s_START=%s %s_END=%s %s_DELTA=%s' "$key" "${first[$key]}" "$key" "${last[$key]}" "$key" "$(delta "${first[$key]}" "${last[$key]}")"
    done
    for key in cpu_some cpu_full memory_some memory_full io_some io_full; do
        printf ' %s_AVG10_START=%s %s_AVG10_END=%s %s_AVG60_START=%s %s_AVG60_END=%s %s_AVG300_START=%s %s_AVG300_END=%s %s_TOTAL_START=%s %s_TOTAL_END=%s %s_TOTAL_DELTA=%s' \
            "$key" "${first[${key}_avg10]}" "$key" "${last[${key}_avg10]}" \
            "$key" "${first[${key}_avg60]}" "$key" "${last[${key}_avg60]}" \
            "$key" "${first[${key}_avg300]}" "$key" "${last[${key}_avg300]}" \
            "$key" "${first[${key}_total]}" "$key" "${last[${key}_total]}" \
            "$key" "$(delta "${first[${key}_total]}" "${last[${key}_total]}")"
    done
    printf ' MEM_PEAK_LIFETIME_START_B=%s MEM_PEAK_LIFETIME_END_B=%s MEM_PEAK_LIFETIME_RISE_B=%s' "${first[memory_peak]}" "${last[memory_peak]}" "$(delta "${first[memory_peak]}" "${last[memory_peak]}")"
}
load_sample() {
    cut -d' ' -f1 /proc/loadavg
}
seconds() {
    printf '%d.%03d' "$(( $1 / 1000000000 ))" "$(( ($1 % 1000000000) / 1000000 ))"
}
add_decimal() {
    awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", a + b }'
}

run_start=$(date -u +%s%N)
run_load_start=$(load_sample)
sample_resources run_before
total_own_user=0
total_own_sys=0
failed=0
environment_failed=0

step() {
    local name=$1
    shift
    local started ended load_start load_end own_user own_sys status time_file
    started=$(date -u +%s%N)
    load_start=$(load_sample)
    sample_resources before
    printf 'STEP-COMMAND=%s ARGV=%s\n' "$name" "${*@Q}"
    time_file=$(mktemp "${TMPDIR:-/tmp}/pn-check-time.XXXXXX") || {
        failed=1
        ended=$(date -u +%s%N)
        load_end=$(load_sample)
        sample_resources after
        printf 'STEP=%s STATUS=2 WALL=%s LOAD_START=%s LOAD_END=%s REASON=no-time-file' "$name" "$(seconds "$((ended - started))")" "$load_start" "$load_end"
        print_resources before after
        printf ' OWN_USER_S=unavailable OWN_SYS_S=unavailable\n'
        return 2
    }
    { time "$@" 2>&3; } 3>&2 2>"$time_file"
    status=$?
    read -r own_user own_sys < "$time_file"
    rm -f "$time_file"
    ended=$(date -u +%s%N)
    load_end=$(load_sample)
    sample_resources after
    total_own_user=$(add_decimal "$total_own_user" "${own_user:-0}")
    total_own_sys=$(add_decimal "$total_own_sys" "${own_sys:-0}")
    if ((status != 0)); then failed=1; fi
    printf 'STEP=%s STATUS=%s WALL=%s LOAD_START=%s LOAD_END=%s' "$name" "$status" "$(seconds "$((ended - started))")" "$load_start" "$load_end"
    print_resources before after
    printf ' OWN_USER_S=%s OWN_SYS_S=%s\n' "${own_user:-unavailable}" "${own_sys:-unavailable}"
}

first_party=(pn pn-credential-generator pn-interchange documents cli-common execwrap pn-testkit pn-records pn-verification pn-host pn-wallet pn-graph pn-epoch pn-act-profile pn-secret-home pn-act-authentication pn-credential-derivation pn-fixtures)
package_args=()
for package in "${first_party[@]}"; do package_args+=(-p "$package"); done
guard_members() {
    local members expected
    members=$(cargo metadata --no-deps --format-version 1 --offline --locked | python3 -I -c 'import json,sys; d=json.load(sys.stdin); ids=set(d["workspace_members"]); ps=[p for p in d["packages"] if p["id"] in ids]; print("\n".join(sorted(p["name"] for p in ps if p["name"] != "regexml"))); print("pn-features=" + ",".join(sorted(f for p in ps if p["name"] == "pn" for f in p["features"])))') || return 2
    expected=$(printf '%s\n' "${first_party[@]}" | LC_ALL=C sort; printf 'pn-features=debug-observation,fixture\n')
    if [[ $members != "$expected" ]]; then printf 'MEMBERS-DECLARED refusal=members-or-node-features-differ\n' >&2; return 1; fi
    printf 'MEMBERS-DECLARED count=%s vendor=regexml\n' "${#first_party[@]}"
}

step compiler-identity bash ci/check.sh --identity
tree_failed=$failed
failed=0
step compiler-age bash ci/check.sh --compiler-age
environment_failed=$failed
failed=$tree_failed
step members-declared guard_members
step format cargo fmt "${package_args[@]}" -- --check
step lint-workspace cargo clippy --workspace --exclude regexml --all-targets \
    --no-deps --offline --locked --profile gate -- -D warnings
step lint-cli-debug cargo clippy -p cli-common --all-targets --no-deps \
    --features debug-observation --offline --locked --profile gate -- -D warnings
step lint-generator-debug cargo clippy -p pn-credential-generator --all-targets --no-deps \
    --features debug-observation --offline --locked --profile gate -- -D warnings
step lint-documents-debug cargo clippy -p documents --all-targets --no-deps \
    --features debug-observation --offline --locked --profile gate -- -D warnings
step lint-node-default cargo clippy -p pn --all-targets --no-deps \
    --offline --locked --profile gate -- -D warnings
step lint-node-no-default cargo clippy -p pn --all-targets --no-deps \
    --no-default-features --offline --locked --profile gate -- -D warnings
step lint-node-debug cargo clippy -p pn --all-targets --no-deps \
    --no-default-features --features debug-observation --offline --locked --profile gate -- -D warnings
step lint-node-fixture cargo clippy -p pn --all-targets --no-deps \
    --no-default-features --features fixture --offline --locked --profile gate -- -D warnings
step lint-node-fixture-debug cargo clippy -p pn --all-targets --no-deps \
    --no-default-features --features debug-observation,fixture --offline --locked --profile gate -- -D warnings
step build-workspace cargo build --workspace --offline --locked --profile gate
step build-node-default cargo build -p pn --offline --locked --profile gate
step build-node-no-default cargo build -p pn --no-default-features --offline --locked --profile gate
step build-node-debug cargo build -p pn --no-default-features --features debug-observation \
    --offline --locked --profile gate
step build-node-fixture cargo build -p pn --no-default-features --features fixture \
    --offline --locked --profile gate
step build-node-fixture-debug cargo build -p pn --no-default-features \
    --features debug-observation,fixture --offline --locked --profile gate
step check-no-default cargo check "${package_args[@]}" --no-default-features --offline --locked --profile gate
step check-epoch-test-support cargo check -p pn-epoch --lib --no-default-features \
    --features test-support --offline --locked --profile gate
step tests-no-services cargo test --workspace --exclude pn-host --exclude pn-wallet \
    --offline --locked --profile gate --no-fail-fast
step tests-host-public cargo test -p pn-host --test public --offline --locked --profile gate --no-fail-fast
step tests-wallet-direct cargo test -p pn-wallet --lib --test layout --test wire --test allocation \
    --offline --locked --profile gate --no-fail-fast
step tests-node-no-default cargo test -p pn --no-default-features --offline --locked --profile gate --no-fail-fast
step tests-node-debug cargo test -p pn --no-default-features --features debug-observation \
    --offline --locked --profile gate --no-fail-fast
step tests-node-fixture cargo test -p pn --no-default-features --features fixture \
    --offline --locked --profile gate --no-fail-fast
step tests-node-fixture-debug cargo test -p pn --no-default-features --features debug-observation,fixture \
    --offline --locked --profile gate --no-fail-fast
printf 'TESTS-OMITTED=pn-host:lib,doctests:service-or-unreviewed;pn-wallet:test-rpc:elements-service\n'
step documents-generate cargo run -p documents --offline --locked --profile gate -- generate check
step documents-render cargo run -p documents --offline --locked --profile gate -- render check
step labels-check "$LINTER_BIN" check --root .

run_end=$(date -u +%s%N)
run_load_end=$(load_sample)
sample_resources run_after
if ((failed)); then gate_exit=1; elif ((environment_failed)); then gate_exit=3; else gate_exit=0; fi
printf 'ENVIRONMENT-EXIT=%s\n' "$environment_failed"
printf 'GATE-EXIT=%s WALL=%s LOAD_START=%s LOAD_END=%s' "$gate_exit" "$(seconds "$((run_end - run_start))")" "$run_load_start" "$run_load_end"
print_resources run_before run_after
printf ' OWN_USER_S=%s OWN_SYS_S=%s\n' "$total_own_user" "$total_own_sys"
exit "$gate_exit"
