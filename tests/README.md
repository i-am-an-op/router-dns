# Reproducible test scope

`go test -race -count=1 ./...` exercises real local files/signatures/journals,
including abrupt child exit, corrupt payload/backup, whole package-generation
rollback, missing exposed-core intent, transaction exclusion, global readiness
deadline and termination of hook children. Service and package operations in
these Go cases use recorded adapters, not OpenWrt. `scripts/package_hook_test.py`
executes captured Docker package hook control flow with only OS paths mapped to
stubs; it also checks the exact installed OpenClash overlay and drift rejection.

The opt-in Go test `TestKernelReadOnlyMountAndMissingTarget` actually binds files
read-only and tests overwrite/rename rejection. Run only in an unprivileged
isolated mount namespace, with `DNS_KERNEL_TEST=1`; never against a real router
root. The UID-map check deliberately permits the recorded workstation user 1000.
Normal CI skips this kernel-specific test and separately runs the actual crash
helper through its parent test.

The maintained `lab.py` generates its own signed DNS zones, TLS certificates and
fault servers. It accepts `--coredns`, `--unbound`, `--mihomo`, `--disable-cache`,
and `--output`. Install `requirements.txt` in a temporary venv with `pip install
--require-hashes -r tests/requirements.txt`. All endpoints are loopback fixtures.
It covers selection/fallback, terminal negative answers, TTL/failure caching,
UDP/TCP truncation, signed/bogus/expired DNSSEC, TLS identity, Fake-IP and flag
preservation. Run inside a disposable network namespace to avoid port collisions.

`paired_runtime_wrapper.py` uses either the identical payload directly under
UID/GID 65534, or an actual Compose container under the same identity/host network.
For the recorded workstation environment, RootlessKit 3.3.0, Engine 29.9.0 and
Compose 5.6.0 run in disposable namespaces. ARM Unbound 1.26.1-r2 uses the same
QEMU and library closure in both methods; CoreDNS/Mihomo are AMD64. These are
not the rootful router candidate versions (Engine 29.6.1-r1/Compose 5.1.4-r1).

The scripts retain explicit `.work`/`.private` payload paths from the maintained
DNS workspace. They do not download binaries or supply household credentials.
Use `prepare_container_lab.py` after populating verified payload paths, normalize
runtime file/parent permissions, make `component-{coredns,unbound,mihomo}` links
to the wrapper, and invoke `paired_runtime_run.sh` through `rootlesskit_probe.sh`.
`DNS_LAB_ROOT` must be a fresh short `/tmp` path. `DNS_PAIR_OUTPUT` keeps every run;
`DNS_PAIR_BENCH=1` adds the common 2,000 UDP + 2,000 TCP workload and process samples.
The probe refuses real host root and never uses the host Docker socket.

Do not compare the old `lab.py` process RSS field across methods: the Compose
wrapper PID is a CLI process. `resource_sampler.py` samples actual backend,
daemon and shim processes. PSS/page sharing differs with vfs image copies;
reported workstation measurements are not ARM memory or latency predictions.
Keep failed runs. A fixture correction must not be described as a resolver fix.
