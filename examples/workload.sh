#!/bin/bash
# Generates some file I/O (opens, reads, writes) so the examples have something to show.
# Usage: ./workload.sh [seconds]   (default 10)
# WORKLOAD_DIR=/store ./workload.sh puts the scratch files under /store.
set -u
secs=${1:-10}
dir=$(mktemp -d "${WORKLOAD_DIR:-/tmp}/workload.XXXXXX")
trap 'rm -rf "$dir"' EXIT
end=$((SECONDS + secs))
while [ $SECONDS -lt $end ]; do
    for i in 1 2 3 4 5; do
        head -c 65536 /dev/urandom > "$dir/file$i"
        cat "$dir/file$i" > /dev/null
        cat /etc/os-release > /dev/null
        getent ahosts localhost > /dev/null
    done
    ls -l "$dir" > /dev/null
    sleep 0.05
done
