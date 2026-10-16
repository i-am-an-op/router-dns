#!/bin/sh
# Called only for a signed package plan after its complete rollback write set is
# durable. Installation is explicit; this adapter never enables/starts services.
set -eu
G=${DNS_GENERATION:?}
# Package arguments are reviewed, one basename per line; no shell evaluation.
set --
while IFS= read -r package; do
    case "$package" in *[!A-Za-z0-9._+-]*|'') exit 64;; esac
    set -- "$@" "$G/packages/$package"
done < "$G/packages.list"
test "$#" -gt 0
# dnsctl has already protected DNS, stopped the reviewed generation and
# unmounted its overlays after journaling a complete rollback set.
# --no-network plus retained package/index/key content removes DNS dependency.
# No --allow-untrusted. Package identity must authenticate against retained indexes.
exec apk --network=no --repositories-file "$G/repositories.list" --keys-dir "$G/keys" \
    add --scripts=no --commit-hooks=no "$@"
