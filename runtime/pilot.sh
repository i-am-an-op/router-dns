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
    SKIP_SYSTEM_IPV6_CHECK=1 bin/mihomo -t -d "state-$MODE/mihomo" -f config/mihomo.yaml >/dev/null 2>&1
    for lane in d1 g1 g2 g3; do
        # Absolute state paths are presented only after the native bind or
        # container mount. Syntax now, real validation through readiness later.
        root/lib/ld-musl-aarch64.so.1 --library-path root/usr/lib:root/lib root/usr/sbin/unbound-checkconf -o interface "config/unbound-$lane.conf" >/dev/null
        test -s "state-$MODE/anchors/$lane/root.key"
    done
    if [ "$MODE" = compose ]; then
        compose config --quiet
        docker --host unix:///var/run/dns-evaluation-docker.sock image inspect "$(cat aux-image-id)" "$(cat coredns-image-id)" >/dev/null
    fi
}
check() { bin/dnsctl probe readiness.json; }
stop() {
    # Idempotent cleanup; never stop a different owner's stack.
    test -f /var/run/dns-evaluation-mode || return 0
    test "$(cat /var/run/dns-evaluation-mode)" = "$MODE" || return 78
    if [ -f /var/run/dns-evaluation-start-attempted ]; then
        if [ "$MODE" = compose ]; then compose down --timeout 10 || return 78
        else ubus call service delete '{"name":"dns-evaluation"}' >/dev/null || return 78; fi
    fi
    if [ "$MODE" = native ] && [ "$BASE/state-native" -ef "$BASE/state" ]; then umount "$BASE/state" || return 78; fi
    rm -f /var/run/dns-evaluation-start-attempted
    rm -f /var/run/dns-evaluation-mode
    if [ "${DNS_PILOT_WATCHDOG:-0}" != 1 ]; then
        ubus call service delete '{"name":"dns-evaluation-watchdog"}' >/dev/null || true
    fi
}
uptime_seconds() { read -r seconds rest < /proc/uptime; printf '%s\n' "${seconds%%.*}"; }
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
    # Owned volatile lock before any mount; cleanup on ordinary startup errors.
    ( set -C; printf '%s\n' "$MODE" > /var/run/dns-evaluation-mode ) || exit 78
    trap 'stop' EXIT
    trap 'exit 78' HUP INT TERM
    if [ "$MODE" = native ]; then
        mkdir -p "$BASE/state"
        mount --bind "$BASE/state-native" "$BASE/state"
    fi
    # A separate procd process survives a lost SSH session and enforces the
    # fixed wall budget. No boot enablement or existing service is changed.
    ubus call service set "{\"name\":\"dns-evaluation-watchdog\",\"instances\":{\"deadline\":{\"command\":[\"$BASE/pilot.sh\",\"watch\",\"$MODE\"],\"term_timeout\":10,\"stdout\":true,\"stderr\":true}}}" >/dev/null
    touch /var/run/dns-evaluation-start-attempted
    if [ "$MODE" = compose ]; then
        compose up -d --no-build --pull never || exit 78
    else
        ubus call service set "$(cat native-services.json)" >/dev/null || exit 78
    fi
    bin/dnsctl wait-probe readiness.json 60 || exit 78
    trap - EXIT HUP INT TERM
    ;;
 check) verify; check ;;
 watch)
    DNS_PILOT_WATCHDOG=1; export DNS_PILOT_WATCHDOG
    trap 'stop' EXIT
    trap 'exit 78' HUP INT TERM
    deadline=$(( $(uptime_seconds) + 900 ))
    # Permit the same 60-second initial readiness period as start.
    sleep 65
    failures=0
    while test -f /var/run/dns-evaluation-mode; do
        test "$(cat /var/run/dns-evaluation-mode)" = "$MODE" || exit 78
        remaining=$(( deadline - $(uptime_seconds) ))
        test "$remaining" -gt 0 || break
        budget=5; test "$remaining" -ge 5 || budget=$remaining
        if bin/dnsctl wait-probe readiness.json "$budget"; then failures=0
        else failures=$((failures+1)); fi
        test "$failures" -lt 3 || break
        remaining=$(( deadline - $(uptime_seconds) ))
        test "$remaining" -gt 0 || break
        delay=5; test "$remaining" -ge 5 || delay=$remaining
        sleep "$delay"
    done
    ;;
 stop) stop ;;
 *) exit 64;;
esac
