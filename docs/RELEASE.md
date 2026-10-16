Offline lifecycle implementation candidate. The native ARM64 and amd64 controller
is tested against real local filesystem transactions, signature/compatibility
failures and abrupt subprocess termination. Runtime service/package adapters use
controlled fixtures in controller tests; this is not router reboot or APK acceptance.

No production release, router installation, deployment-method selection, operator
assignment or signing-key acceptance is implied. Core/protected-profile integration
and the added-stack pilot have separate activation steps. Read OPERATIONS.md and
the maintained DNS project decision/handoff before any router action.
