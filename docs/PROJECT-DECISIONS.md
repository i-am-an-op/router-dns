# User scope and decision continuity

16 October 2026. **User position: “evaluate Compose fairly; deployment choice undecided.”** This is the maintained repository copy of the controlling DNS-project decision record. A pilot, fork, passing CI or draft release is not acceptance of a production architecture.

Accepted scope: complete DNS for MT5000 and MT6000 LANs and connected phones, preserving existing application-routing roles. MT5000 applications are not automatically proxied through MT6000. Roaming and remote access are excluded. Compare only the additional DNS components under native versus Compose; router OS/firewall/DHCP/clock/existing OpenClash integration are not being containerized.

Off-router implementation, research, isolated tests, review PRs under **i-am-an-op** and attested unpublished candidates are authorized. No subagents. Credentials remain private. No router upload/install/start or live DNS/service/firewall/routing/DHCP/clock change, and no production release publication, without a separately reviewed deployment step.

No runtime choice, shared/separate transport placement, managed-API restriction, production architecture, review-key owner, operator, notification channel or perpetual maintenance arrangement has been accepted. The chat is not ongoing operations.

Compare the same resolver policy and equivalent binaries/libraries/trust stores/configurations/workloads. Separate shared requirements from deployment/network-mode effects, measurements and hypotheses. Time/bootstrap/TLS/DNSSEC/readiness/state/recovery apply to both; they do not by themselves favor native. Docker is not synonymous with default bridge networking; host mode also needs actual identity/interception tests. Give Compose repeatability, isolation, version management and convenience fair weight. Measure overhead and failure behavior; do not extrapolate workstation/QEMU results to a router winner.

The user-updated baseline is OpenClash0.48.002 plus alpha-gbc76c13, Go1.26.9/ARM64. The captured init is locally modified. Do not restore older versions merely to match an obsolete proposal. Source pins, generated-profile fingerprints and artifact digests must be refreshed through review after a user update.

Conditional agent recommendation: retain both runtime candidates for target comparison, with existing native client-facing roles and the active frontend fix while its required semantics cannot be obtained from a supported official binary. A patched transport does not fix an unchanged frontend. Official numeric byte transport is separately viable within its tested scope. Return to official Mihomo after equivalent semantic/application/lifecycle evidence, or reopen architecture if fork maintenance cannot be sustained.

All future handoffs must preserve the decision wording and distinguish user requirements, accepted decisions, observed facts, actual execution, simulations, recommendations and untested proposals. Current artifacts/tests and target gates are in [CANDIDATE-STATUS.md](CANDIDATE-STATUS.md); transaction boundaries and maintenance duties are in [OPERATIONS.md](OPERATIONS.md).
