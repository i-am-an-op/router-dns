# Router DNS integration candidates

Maintained review work for i-am-an-op. This repository implements off-router
preparation and the proposed MT6000 integration controller; it is not an accepted
production deployment. Complete DNS serves the MT5000 and MT6000 LANs while
preserving their application-routing roles. No roaming or remote-access scope.

**Evaluate Compose fairly; deployment choice undecided.** Native and host-network
Compose use identical resolver payloads, policy, state layout and workloads.
The existing OpenClash frontend remains native in either candidate.

Build with official Go 1.26.9: `go mod verify && go test -race ./...`, then
`CGO_ENABLED=0 go build -trimpath -o dist/dnsctl ./cmd/dnsctl`.
The controller uses a pinned YAML library and the standard library. Generation runtime
operations require root and an explicit locally trusted review key; `--offline`
prohibits mutation. Standalone probes intentionally query DNS; owned-service stop
requires native root and rejects `--offline`. Never run the production adapters as an isolated pilot.

The review signature authorizes exact private payload bytes. It is separate from
GitHub build provenance and from the user's authorization to deploy. No accepted
operator, notification channel, signing key or perpetual maintenance arrangement
is implied by this repository. No production release is authorized.

[Current candidates and evidence](docs/CANDIDATE-STATUS.md) and
[user decisions/authorization](docs/PROJECT-DECISIONS.md) govern future handoffs.
