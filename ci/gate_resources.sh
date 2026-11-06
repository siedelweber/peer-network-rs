#!/usr/bin/env bash
# Nonbinding raw samples. Epoch fields are Unix UTC seconds; kernel units are
# retained verbatim and interpreted once by gate_resources.py at gate end.
export GATE_RESOURCE_READER="${BASH_SOURCE[0]%/*}/gate_resources.py"
gate_cgroup_root() {
    local hierarchy controllers relative candidate
    while IFS=: read -r hierarchy controllers relative; do
        if [[ $hierarchy == 0 && -z $controllers ]]; then
            candidate="/sys/fs/cgroup${relative}"
            if [[ -e "$candidate/cgroup.procs" ]]; then printf '%s' "$candidate"; else printf /sys/fs/cgroup; fi
            return
        fi
    done < /proc/self/cgroup
}
gate_resource_sample() {
    local destination=$1 root=$2 proc=${3:-/proc} file value
    {
        printf 'epoch_seconds=%s\ncgroup=%s\n' "$EPOCHREALTIME" "$root"
        for file in cpu.stat cpu.pressure memory.pressure io.pressure memory.current memory.peak; do
            printf '[%s]\n' "$file"
            if [[ -n "$root" && -r "$root/$file" ]]; then
                value=$(<"$root/$file")
                printf '%s\n' "$value"
            else
                printf 'unavailable\n'
            fi
        done
        for file in pressure/cpu pressure/memory pressure/io loadavg stat; do
            printf '[proc/%s]\n' "$file"
            if [[ -r "$proc/$file" ]]; then
                value=$(<"$proc/$file")
                printf '%s\n' "$value"
            else
                printf 'unavailable\n'
            fi
        done
        printf '[scope]\n'
        python3 -B "$GATE_RESOURCE_READER" --scope "$root" "$proc"
        printf '[clock-ticks]\n'
        getconf CLK_TCK
    } > "$destination"
}
