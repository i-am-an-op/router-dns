# Review contract and operational boundaries

The controller and adapters are implementation candidates, not router acceptance.
Its Ed25519 review signature covers the exact manifest, which covers every private
payload byte and mode, ELF architecture, compatibility pins, DNS/application
fingerprints and provenance verification receipts. Signature validity does not
constitute deployment authorization. No production review key has been appointed.

The offline workstation verifier first checks GitHub's signed build attestation,
expected numeric repository ID, source commit, workflow/ref and artifact digest.
It retains the Sigstore trusted root and bundle. A reviewer then signs a private
generation manifest using a separate offline key; the router only needs the public
review key and retained payloads. Offline recovery never fetches stock binaries.
Repository authentication and artifact subject checks follow [GitHub offline
verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline).
The signature proves origin under that local trust decision; it does not establish
correctness or a SLSA level. See [SLSA 1.2 verification](https://slsa.dev/spec/v1.2/verifying-artifacts).

A generation owns the frontend binary, rendered profile, protected OpenClash
helpers, updater blocks, mode-specific launch configuration and common DNS policy.
Profiles are staged off-router; DNS/IPv6 come from the reviewed policy while all
other semantic changes produce a separate application fingerprint. Neither a
subscription download nor a dashboard editor is allowed to reload live policy.
Geo/rule updates require review too; selection among already configured proxies
remains available. Explicit client/application DoH overrides are outside port-53
interception and must be tested/managed on the LAN clients.

`stage` checks signatures, the complete file set, modes, hashes and installed
package pins. `promote` validates capabilities/configuration before stopping,
protects DNS, journals each phase, stops the prior generation, switches read-only
binds, starts dependencies, checks readiness and only then publishes state.
Files and enclosing directories are fsynced. Power-loss semantics on the router's
actual storage remain a bounded router test; a workstation process exit is not
proof of F2FS or overlay power-loss durability.

`recover` restores a whole accepted generation after an incomplete transaction.
The accepted-state publication is the commit point. `boot` verifies retained
payloads, reapplies missing exposed-core binds, starts the frontend before DNS
readiness, and uses the verified previous generation if current payloads fail.
It refuses stock-core downloads when both fail. Artifact failures before promotion
do not stop a healthy application core. Root can intentionally bypass controls;
this is not secure boot. Source/mount topology changes need a separately reviewed
migration rather than silently expanding a transaction's write set.

The watchdog checks integrity and functional readiness every 15 seconds. Three
consecutive readiness failures trigger DNS-stack-only repair, capped at three
attempts; it does not kill the application frontend on identity drift. A local
health record reports failure. An operator must investigate persistent failure.
procd/Compose process monitoring does not prove health; readiness probes cover
multiple response classes and transports, while the full acceptance suite covers
fallback, signed/bogus/expired data, cache flags/TTL and application routing.

Package transactions use a separately signed complete write set and archived
previous bytes/database/world. No generic `apk add` is permitted through the
managed UI. New package scripts/commit hooks are suppressed. Recovery validates
all backups before restoration. Plans currently restrict the write set to regular
files; symlink/directory migrations require a new reviewed adapter. The off-router
APK extraction/solver supplies the write set; the router test must check actual
writes and package DB consistency. A package transaction is not committed until
its compatible generation has passed readiness. Offline backups must remain
available through reboot. Preserve mutable validator anchor state: each lane and
runtime has an independent writable directory. Whole-generation rollback does
not roll trust-anchor time/state backwards; [RFC 5011 §§2.3–2.4, 4–5](https://www.rfc-editor.org/rfc/rfc5011)
defines hold-down and state-machine behavior, not a choice of deployment method.

OpenClash 0.48.002 tag e553e82e01c697aefbe1555261a503f425e00ccd is the
package baseline; the actual installed init is a captured local modification.
The renderer pins both, blocks current upload/editor/update paths and bypasses
on-router profile rewriting in favor of a reviewed rendered profile. Source:
[0.48.002 controller](https://github.com/vernesong/OpenClash/blob/e553e82e01c697aefbe1555261a503f425e00ccd/luci-app-openclash/luasrc/controller/openclash.lua)
and [core updater](https://github.com/vernesong/OpenClash/blob/e553e82e01c697aefbe1555261a503f425e00ccd/luci-app-openclash/root/usr/share/openclash/openclash_core.sh).

Both runtime candidates share the same clock, bootstrap, validation and recovery
requirements. Host networking preserves loopback topology but still requires
router verification of numeric GID 65534, nft interception, IPv6 and listener ACLs.
The verified OpenWrt Docker 29.6.1-r1 package starts services and adds UCI network
configuration in its post-install hook; the candidate suppresses it and uses a
separate daemon configuration. This is a packaging difference, not a DNS protocol
requirement. Compose offers repeatable service declarations and dependency
isolation. Native avoids the additional Engine/containerd layer. Resource and
failure comparisons require equivalent router workloads before selecting either.

No operator, external notification destination or perpetual maintenance agreement
is accepted. GitHub schedules can be delayed or disabled; an independently run
maintenance checker must alert on absent runs, failure and stale operator review.
If maintenance stops, freeze promotion, retain the last accepted offline payload,
and review a return to official Mihomo or a resolver/traffic architecture that
passes the same tests without the patch. Do not equate a frozen binary with
continued security maintenance. NIST [SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
PO.2/PO.3/PO.4, PS.1–PS.3, PW.4/PW.7/PW.8 and RV.1–RV.3 guide ownership,
provenance, testing and vulnerability response; this project claims no certification.

## Implemented off-router boundaries

Package rollback retains the original regular files, UID/GID/modes and APK
installed/world databases. A package history record links its old and new DNS
generations, allowing whole-generation rollback to restore the matching package.
Unenumerated files and symlink migrations are refused. The generic adapter does
not pretend an arbitrary future package has a known write set: extract and review
that exact signed package before making its signed plan. APK runs with script and
commit hooks disabled, and hook timeout kills the entire child process group.

Production DNS stack state is initialized only when absent and remains outside
the immutable generations. Both methods use numeric UID/GID 65534 for added
processes; OpenClash keeps its existing root:GID65534 identity. Configurations in
the root-only store are exposed through protected bind targets beneath group-only
traversable directories. Compose additionally restricts each service's bind set.
Native procd and Compose restart policies are bounded; the common controller
handles unhealthy-but-running services. Repair is serialized against updates.

A concrete unsigned generation can be prepared with `frontend_profile.py`,
`prepare_generation.py` and `assemble_bootstrap.py`. Shared and separate transport
are explicit arguments; shared mode starts the frontend before dependent DNS and
removes the duplicate transport service. The bootstrap tree is not activated and
will lack an accepted public review key unless one is supplied. Initial conversion
from unmanaged OpenClash also requires an authenticated complete baseline backup,
boot-link transfer and the separately reviewed firewall/client cutover. A failed
initial promotion has no accepted older generation; it retains DNS protection and
requires restoration of that reviewed baseline. Do not claim this is zero downtime.

The managed frontend blocks config reload/patch, restart, core/geo upgrade,
rule-disable changes and rule-provider API replacement before handler execution.
It preserves reads and existing proxy selection. Proxy-provider refresh and some
cache/UI operations remain available. The profile renderer disables geodata auto
update; provider URLs/files and their update behavior still require application
routing review. This is not a guarantee that every mutable Mihomo feature is blocked.

Security automation is enabled and manually exercised, but 37 open Dependabot
alerts were observed in the inherited separate Mihomo `test/go.mod` module. They
are not a finding of a clean repository, nor evidence that all affect the shipped
root-module binary. The production scanner runs on both architectures. Legacy
interop-module advisory disposition is a human review item and must remain visible.
No external notification has been sent or configured as an accepted operation.
