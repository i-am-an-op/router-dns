#!/bin/sh
# Both candidates share the fixed procd/Compose project name. Stop only that
# stack, allowing recovery even when the new candidate's method differs.
set -eu
/usr/libexec/dnsctl stop-service dns-evaluation
if command -v docker >/dev/null && [ -S /var/run/dns-evaluation-docker.sock ]; then
    ids=$(docker --host unix:///var/run/dns-evaluation-docker.sock ps -aq --filter label=com.docker.compose.project=dns-evaluation)
    if [ -n "$ids" ]; then
        docker --host unix:///var/run/dns-evaluation-docker.sock stop --time 10 $ids >/dev/null
    fi
fi
