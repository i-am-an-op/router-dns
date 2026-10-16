#!/bin/sh
# WORKSTATION ONLY. Run inside a disposable user/mount/net/PID namespace.
# No package installation, host sysctls/firewall or global Docker service.
set -eu
: "${DNS_LAB_ROOT:?Set an empty workspace directory}"
test "$(id -u)" = 0
# Refuse real host root: namespace root must map to an unprivileged outer UID.
test "$(awk 'NR==1 {print $1}' /proc/self/uid_map)" = 0
test "$(awk 'NR==1 {print $2}' /proc/self/uid_map)" != 0
test "$(awk 'NR==1 {print $3}' /proc/self/uid_map)" = 1
mkdir -p "$DNS_LAB_ROOT/runtime" "$DNS_LAB_ROOT/rootless" "$DNS_LAB_ROOT/data" "$DNS_LAB_ROOT/exec"
ip link set lo up
# /run is private to this temporary mount namespace, including plugin sockets.
mount -t tmpfs -o mode=755 tmpfs /run
export XDG_RUNTIME_DIR="$DNS_LAB_ROOT/runtime"
# Moby supports running inside an existing user namespace without RootlessKit.
# This is a workstation fixture, not a claim of router/rootful equivalence.
unset ROOTLESSKIT_STATE_DIR
printf '{}\n' > "$DNS_LAB_ROOT/daemon.json"
dockerd --group 0 --config-file "$DNS_LAB_ROOT/daemon.json" \
  --host "unix://$DNS_LAB_ROOT/docker.sock" \
  --data-root "$DNS_LAB_ROOT/data" --exec-root "$DNS_LAB_ROOT/exec" \
  --pidfile "$DNS_LAB_ROOT/daemon.pid" --storage-driver vfs \
  --bridge none --iptables=false --ip6tables=false --ip-forward=false \
  --ip-masq=false --userland-proxy=false \
  --exec-opt native.cgroupdriver=cgroupfs > "$DNS_LAB_ROOT/daemon.log" 2>&1 &
daemon_pid=$!
trap 'kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true' EXIT INT TERM
i=0
while [ "$i" -lt 20 ]; do
  if docker -H "unix://$DNS_LAB_ROOT/docker.sock" info --format '{{json .}}' > "$DNS_LAB_ROOT/info.json" 2> "$DNS_LAB_ROOT/info.stderr"; then
    printf 'Isolated daemon responded\n'
    if [ -n "${DNS_LAB_IMAGE:-}" ]; then
      docker -H "unix://$DNS_LAB_ROOT/docker.sock" import "$DNS_LAB_IMAGE" dns-lab:local > "$DNS_LAB_ROOT/image-id.txt"
      docker -H "unix://$DNS_LAB_ROOT/docker.sock" run --rm --network host --user 65534:65534 \
        --cap-drop ALL --security-opt no-new-privileges:true --read-only \
        dns-lab:local /bin/coredns -version
    fi
    if [ -n "${DNS_LAB_COMMAND:-}" ]; then
      export DOCKER_HOST="unix://$DNS_LAB_ROOT/docker.sock"
      sh -c "$DNS_LAB_COMMAND"
    fi
    exit 0
  fi
  kill -0 "$daemon_pid" 2>/dev/null || break
  i=$((i+1)); sleep 1
done
tail -15 "$DNS_LAB_ROOT/daemon.log"
exit 1
