#!/bin/sh
# Executed only by dnsctl after verifying this generation's signature and files.
set -eu
G=${DNS_GENERATION:?}
S=${DNS_STORE:?}
CTL=/usr/libexec/dnsctl
BASE=/opt/dns-evaluation/20261016-rc1
compose() {
    DNS_EVAL_ROOT="$BASE" DNS_AUX_IMAGE="$(cat "$G/config/aux-image-id")" \
    docker --host unix:///var/run/dns-evaluation-docker.sock compose \
      --project-directory "$BASE" -f "$G/config/compose.yaml" "$@"
}
stack_start() {
    "$G/runtime/state-prepare.sh"
    if [ "$DNS_MODE" = compose ]; then
        compose up -d --no-build --pull never --wait --wait-timeout 60
    else
        ubus call service set "$(cat "$G/config/native-services.json")" >/dev/null
    fi
}
stack_stop() {
    "$G/runtime/stop-all-stack.sh"
}

case "${1:-}" in
 preflight)
    # No network, process stop, config mutation or DNS-dependent artifact lookup.
    test "$("$G/bin/clash_meta" -dns-managed-capabilities)" = '{"schema":1,"dns_disable_cache":true,"managed_frontend":true,"mutation_guard":1}'
    MIHOMO_MANAGED_DNS=1 "$G/bin/clash_meta" -t -d /etc/openclash -f "$G/config/frontend.yaml" >/dev/null 2>&1
    for lane in d1 g1 g2 g3; do
        "$G/stack/root/lib/ld-musl-aarch64.so.1" --library-path "$G/stack/root/usr/lib:$G/stack/root/lib" \
          "$G/stack/root/usr/sbin/unbound-checkconf" "$G/stack/config/unbound-$lane.conf" >/dev/null
    done
    if [ "$DNS_MODE" = compose ]; then
        docker --host unix:///var/run/dns-evaluation-docker.sock info >/dev/null
        compose config --quiet
        # No implicit image pulls during boot or failure recovery.
        for image in "$(cat "$G/config/aux-image-id")" "$(cat "$G/config/coredns-image-id")"; do
            docker --host unix:///var/run/dns-evaluation-docker.sock image inspect "$image" >/dev/null
        done
    fi
    ;;
 protect) "$G/runtime/protect.sh" ;;
 mount) "$CTL" --store "$S" runtime mount "${G##*/}" ;;
 unmount) "$CTL" --store "$S" runtime unmount "${G##*/}" ;;
 start)
    # Frontend is allowed to start before external resolver readiness: its
    # numeric shared transport must not wait on DNS that depends on it.
    /etc/init.d/openclash start
    stack_start
    ;;
 stop)
    stack_stop
    /etc/init.d/openclash stop
    ;;
 health)
    "$CTL" --store "$S" runtime protected
    # Clock readiness is shared. This neither sets the clock nor disables TLS.
    chronyc waitsync 1 0.5 0 1 >/dev/null 2>&1
    test "$(curl --silent --show-error --max-time 3 --config "$G/config/api-check.curl" --output /dev/null --write-out '%{http_code}')" = 409
    "$CTL" --store "$S" runtime probe
    ;;
 repair-dns)
    # Explicit, bounded repair; preserve the application frontend. Shared
    # transport failures remain visible and require guarded frontend recovery.
    "$CTL" --store "$S" runtime protected
    stack_stop
    stack_start
    "$CTL" --store "$S" runtime probe
    ;;
 *) exit 64 ;;
esac
