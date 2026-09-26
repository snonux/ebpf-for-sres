#!/bin/bash
# Generates some file I/O (opens, reads, writes) so the examples have something to show.
# Usage: ./workload.sh [seconds]   (default 10)
set -u
secs=${1:-10}
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
end=$((SECONDS + secs))
while [ $SECONDS -lt $end ]; do
    for i in 1 2 3 4 5; do
        head -c 65536 /dev/urandom > "$dir/file$i"
        cat "$dir/file$i" > /dev/null
        cat /etc/os-release > /dev/null
    done
    ls -l "$dir" > /dev/null
    sleep 0.05
done
