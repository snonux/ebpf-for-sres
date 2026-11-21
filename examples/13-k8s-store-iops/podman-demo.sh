#!/bin/bash
# The Kubernetes debug-container workflow from README.md, rehearsed with podman
# on a single Rocky 9 box (no cluster needed). Good for a live demo.
#
#   1. "app": a distroless-style container writing to /store (a tmpfs volume
#      standing in for an EFS mount).
#   2. "debug": a privileged container that joins app's PID namespace, like
#      kubectl debug --target=app --profile=sysadmin.
#   3. The static storeiops binary is copied in and traces app's /store I/O.
#
# Run: sudo ./podman-demo.sh [seconds]   (needs: podman, and ./storeiops built
#      with "mage static"; set DEBUG_IMAGE to try another debug image)
set -euo pipefail
cd "$(dirname "$0")"
secs=${1:-10}
APP_IMAGE=${APP_IMAGE:-registry.access.redhat.com/ubi9/ubi-minimal:latest}
DEBUG_IMAGE=${DEBUG_IMAGE:-docker.io/library/busybox:latest}

[ -x storeiops ] || { echo "build it first: mage static"; exit 1; }
cleanup() { podman rm -f -t 0 storeiops-app storeiops-debug >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "== Starting app container with /store"
podman run -d --name storeiops-app --mount type=tmpfs,destination=/store "$APP_IMAGE" \
    sh -c 'while true; do
             dd if=/dev/zero of=/store/data bs=4k count=64 conv=fsync status=none
             cat /store/data > /dev/null
             cat /etc/os-release > /dev/null   # not on /store: must not show up
             sleep 0.1
           done'

echo "== Starting debug container in app's PID namespace"
podman run -d --name storeiops-debug --privileged --pid=container:storeiops-app \
    --entrypoint /bin/sh "$DEBUG_IMAGE" -c 'sleep 3600'
# Same as: kubectl cp storeiops <pod>:/tmp/storeiops -c <debug-container>
podman cp storeiops storeiops-debug:/tmp/storeiops

echo "== Processes the debug container sees (app's, PID 1 is app):"
podman exec storeiops-debug ps
echo
echo "== Tracing /store of PID 1 for ${secs}s"
podman exec storeiops-debug /tmp/storeiops -pid 1 -path /store -bycomm -duration "${secs}s"
