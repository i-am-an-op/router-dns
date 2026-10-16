#!/bin/sh
# WORKSTATION ONLY, invoked under a disposable rootless Engine/network namespace.
set -eu
: "${DOCKER_HOST:?}" "${DNS_PAIR_ROOTFS:?}" "${DNS_PAIR_OUTPUT:?}"
mkdir -p /tmp/dns-matched-payload
mount --bind "$DNS_PAIR_ROOTFS" /tmp/dns-matched-payload
export DNS_PAIR_ROOTFS=/tmp/dns-matched-payload
export DNS_PAIR_IMAGE=dns-lab:local DNS_LAB_STARTUP_DELAY=2
mkdir -p "$DNS_PAIR_OUTPUT"
for mode in ${DNS_PAIR_MODES:-native compose}; do
    export DNS_PAIR_MODE="$mode"
    .work/venv/bin/python tests/lab.py --coredns .work/pair-wrappers/component-coredns \
      --unbound .work/pair-wrappers/component-unbound --mihomo .work/pair-wrappers/component-mihomo \
      --disable-cache --output "$DNS_PAIR_OUTPUT/$mode.json" > "$DNS_PAIR_OUTPUT/$mode.stdout" 2> "$DNS_PAIR_OUTPUT/$mode.stderr" || status=$?
    docker ps --format '{{.ID}}' > "$DNS_PAIR_OUTPUT/$mode-containers-after.txt"
    # Cleanup is confined to this disposable daemon, containing only test fixtures.
    ids=$(docker ps -aq)
    if [ -n "$ids" ]; then docker rm -f $ids >/dev/null; fi
    if [ "${status:-0}" -ne 0 ]; then exit "$status"; fi
done
