#!/bin/sh
# WORKSTATION ONLY; called by the disposable namespace daemon probe.
set -eu
: "${DOCKER_HOST:?Private test daemon required}"
PAIR=${DNS_IMAGE_PAIR:-.private/mt6000-deployment-pair-20261016-r2}
OUT=${DNS_IMAGE_OUTPUT:-.work/paired-images}
mkdir -p "$OUT"
docker load -i .work/coredns-offline-arm64.tar > "$OUT/coredns-load.log" 2>&1
docker image inspect sha256:5d3b3e589fcf57f626c7967bff5171924cf9c55068911247a1f7bd2458e726c3 > "$OUT/coredns-inspect.json"
# COPY-only scratch build: no image pull, RUN instruction or workload execution.
docker build --network none --pull=false --platform linux/arm64 \
  -t dns-evaluation/aux:20261016-rc1 "$PAIR/image-context" > "$OUT/aux-build.log" 2>&1
docker image inspect dns-evaluation/aux:20261016-rc1 > "$OUT/aux-inspect.json"
docker save -o "$OUT/aux-offline.tar" dns-evaluation/aux:20261016-rc1
printf '%s\n' 'Offline CoreDNS image found by original image ID; auxiliary scratch image built/exported.'
