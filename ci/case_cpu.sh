#!/usr/bin/env bash
# Meter one nextest process and its reaped descendants without a Python startup.
if [ -z "${NEXTEST_TEST_NAME+x}" ]; then exec "$@"; fi
set -u
export LC_ALL=C
base="${PN_GATE_CASE_CPU:?}/$BASHPID"
trap 'rm -f "$base.time"' EXIT
exec 3>&2
TIMEFORMAT='PN-CASE-TIME %R %U %S'
{ time "$@" 2>&3; } 2>"$base.time"
status=$?
wall= user= system=
while IFS= read -r line; do
    if [[ "$line" == PN-CASE-TIME\ * ]]; then
        read -r marker wall user system <<< "$line"
    else
        printf '%s\n' "$line" >&2
    fi
done < "$base.time"
set -o noclobber
printf '%s\0' "$NEXTEST_BINARY_ID::$NEXTEST_TEST_NAME" "$PN_HARNESS_SOURCE" "$status" "$wall" "$user" "$system" > "$base.cpu"
exit "$status"
