#!/bin/sh
# WORKSTATION ONLY; called by the disposable namespace daemon probe.
set -eu
: "${DOCKER_HOST:?Private test daemon required}"
: "${DNS_LAB_ROOT:?Disposable namespace daemon required}"
test "$DOCKER_HOST" = "unix://$DNS_LAB_ROOT/docker.sock"
test "$(awk 'NR==1 {print $2}' /proc/self/uid_map)" != 0
test "$(awk 'NR==1 {print $3}' /proc/self/uid_map)" = 1
PAIR=${DNS_IMAGE_PAIR:?Select the reviewed pair explicitly}
OUT=${DNS_IMAGE_OUTPUT:?Use a new output directory}
mkdir -p "$OUT"
python3 "$(dirname "$0")/../scripts/verify_image_archive.py" \
  --archive .work/coredns-offline-arm64.tar \
  --expected-sha256 0d2dacb31f793295a816f71442d470a60b6c2dbd6bf7d034b0e1f2f537783407 \
  --output "$OUT/coredns-archive-structure.json"
docker load -i .work/coredns-offline-arm64.tar > "$OUT/coredns-load.log" 2>&1
docker image inspect sha256:5d3b3e589fcf57f626c7967bff5171924cf9c55068911247a1f7bd2458e726c3 > "$OUT/coredns-inspect.json"
# COPY-only scratch build: no image pull, RUN instruction or workload execution.
docker build --network none --pull=false --platform linux/arm64 \
  -t dns-evaluation/aux:20261016-rc1 "$PAIR/image-context" > "$OUT/aux-build.log" 2>&1
docker image inspect dns-evaluation/aux:20261016-rc1 > "$OUT/aux-inspect.json"
docker save -o "$OUT/aux-offline.tar" dns-evaluation/aux:20261016-rc1
printf '%s\n' 'Offline CoreDNS image found by original image ID; auxiliary scratch image built/exported.'
