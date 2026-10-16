#!/bin/sh
# OFF-ROUTER ROOT ASSEMBLY by default. A router invocation is a separately
# reviewed deployment step. No service start, package install or DNS mutation.
set -eu
test "$#" = 2 || exit 64
PAYLOAD=$1
TARGET=$2
case "$TARGET" in /) echo 'Use the reviewed router transaction; direct host-root install refused.' >&2; exit 78;; /*) ;; *) exit 64;; esac
# The caller verifies this source/controller attestation and review-key identity
# independently. A checksum file from the same archive is not authentication.
cd "$PAYLOAD"
sha256sum -c bootstrap.SHA256SUMS >/dev/null
install -d -m 700 "$TARGET/etc/dns-core" "$TARGET/opt/dns-core/generations"
install -d -m 755 "$TARGET/usr/libexec" "$TARGET/etc/init.d" "$TARGET/etc/rc.d"
install -m 755 dnsctl "$TARGET/usr/libexec/dnsctl"
install -m 755 dns-core-guard "$TARGET/usr/libexec/dns-core-guard"
install -m 755 dns-core-gate.init "$TARGET/etc/init.d/dns-core-gate"
install -m 644 review.pub "$TARGET/etc/dns-core/review.pub"
# Explicitly prepared boot ownership. No command is executed by these links.
rm -f "$TARGET/etc/rc.d/S99openclash"
ln -s ../init.d/dns-core-gate "$TARGET/etc/rc.d/S98dns-core-gate"
