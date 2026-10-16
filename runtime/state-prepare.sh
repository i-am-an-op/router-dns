#!/bin/sh
# Mutable RFC5011 state survives generation replacement and rollback.
set -eu
G=${DNS_GENERATION:?}
BASE=/opt/dns-evaluation/20261016-rc1
case "${DNS_MODE:?}" in native|compose) ;; *) exit 64;; esac
STATE="$BASE/state-$DNS_MODE"
for lane in d1 g1 g2 g3; do
    target="$STATE/anchors/$lane"
    test ! -L "$target"
    mkdir -p "$target"
    chown 65534:65534 "$STATE" "$STATE/anchors" "$target"
    chmod 750 "$STATE" "$STATE/anchors" "$target"
    if [ ! -e "$target/root.key" ]; then
        # Only initialize an absent lane; never overwrite an accepted anchor.
        ( set -C; umask 077; cat "$G/config/root-seed.key" > "$target/root.key" )
        chown 65534:65534 "$target/root.key"
    fi
    test ! -L "$target/root.key"
done
mkdir -p "$STATE/mihomo"
chown 65534:65534 "$STATE/mihomo"
chmod 750 "$STATE/mihomo"
if [ "$DNS_MODE" = native ]; then
    mkdir -p "$BASE/state"
    if ! [ "$STATE" -ef "$BASE/state" ]; then
        # Refuse replacing an unrelated mount.
        ! awk -v p="$BASE/state" '$5==p {found=1} END {exit !found}' /proc/self/mountinfo
        mount --bind "$STATE" "$BASE/state"
    fi
fi
