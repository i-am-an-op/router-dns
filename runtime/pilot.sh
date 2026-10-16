#!/bin/sh
# Explicitly invoked, isolated added-stack pilot. Never changes LAN DNS, routing,
# DHCP, clock, OpenClash or firewall. No package installation or image download.
set -eu
BASE=/opt/dns-evaluation/20261016-rc1
MODE=${2:-}
case "$MODE" in native|compose) ;; *) exit 64;; esac
cd "$BASE"
compose() { DNS_EVAL_ROOT="$BASE" DNS_AUX_IMAGE="$(cat aux-image-id)" docker --host unix:///var/run/dns-evaluation-docker.sock compose --env-file /dev/null -f compose.yaml "$@"; }
verify() {
    sha256sum -c pilot.SHA256SUMS >/dev/null
    chronyc waitsync 1 0.5 0 1 >/dev/null 2>&1
    # Both modes require the same numeric upstream transport and validator CA.
    bin/mihomo -t -d "state-$MODE/mihomo" -f config/mihomo.yaml >/dev/null 2>&1
    for lane in d1 g1 g2 g3; do
        root/lib/ld-musl-aarch64.so.1 --library-path root/usr/lib:root/lib root/usr/sbin/unbound-checkconf "config/unbound-$lane.conf" >/dev/null
    done
    if [ "$MODE" = compose ]; then
        compose config --quiet
        docker --host unix:///var/run/dns-evaluation-docker.sock image inspect "$(cat aux-image-id)" "$(cat coredns-image-id)" >/dev/null
    fi
}
check() { bin/dnsctl probe readiness.json; }
case "${1:-}" in
 preflight) verify ;;
 start)
    verify
    # One candidate owns the fixed loopback ports at a time. Fail if occupied.
    test ! -e /var/run/dns-evaluation-mode
    for p in 6053 6054 6060 6061 6063 6064 6065 6183 6184 6185 17874 17890; do
        hex=$(printf '%04X' "$p")
        # /proc avoids assuming an ss package; both TCP and UDP, v4 and v6.
        ! awk -v suffix=":$hex" '$2 ~ (suffix "$") {found=1} END {exit !found}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6
    done
    if [ "$MODE" = native ]; then
        mkdir -p "$BASE/state"
        mount --bind "$BASE/state-native" "$BASE/state"
    fi
    # Persist only volatile pilot ownership; no boot enablement.
    printf '%s\n' "$MODE" > /var/run/dns-evaluation-mode
    if [ "$MODE" = compose ]; then
        compose up -d --no-build --pull never || { "$0" stop "$MODE"; exit 78; }
    else
        ubus call service set "$(cat native-services.json)" >/dev/null || { "$0" stop "$MODE"; exit 78; }
    fi
    bin/dnsctl wait-probe readiness.json 60 || { "$0" stop "$MODE"; exit 78; }
    ;;
 check) verify; check ;;
 stop)
    test "$(cat /var/run/dns-evaluation-mode)" = "$MODE"
    if [ "$MODE" = compose ]; then compose down --timeout 10
    else ubus call service delete '{"name":"dns-evaluation"}' >/dev/null; fi
    if [ "$MODE" = native ]; then umount "$BASE/state"; fi
    rm /var/run/dns-evaluation-mode
    ;;
 *) exit 64;;
esac
