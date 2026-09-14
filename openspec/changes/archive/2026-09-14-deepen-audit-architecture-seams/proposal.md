## Why

The architecture review found several related seams where implementation knowledge leaks across the audit filter:

- `auditserver.New(logger)` depends on hidden global Viper state while constructing rules, log writers, messaging, forwarding, async settings, durable retry, and transport policy.
- `RuleGroup` exposes a field bag whose nil combinations are interpreted by frame handling code.
- Async side-effect behavior is meaningful, but its queue, store, retry, and timer details are tested and called through low-level internals.
- gnet/TCP/UDP framing sits in the same module as audit filtering behavior.
- Vault socket audit setup leaks raw option-map keys into commands and integration tests.
- Integration tests repeat Vault, listener, wait, and assertion wiring.

These are not separate cleanups. They overlap around startup construction, audit frame processing, and test harnesses. Treating them as one staged architecture change keeps behavior stable while improving locality and leverage.

## What Changes

- Add an explicit configuration assembly module that reads Viper in command code and passes normalized typed settings into runtime modules.
- Deepen rule group execution so matching, log writing, payload preparation, and side-effect request creation live behind one rule group seam.
- Raise the side-effect processor seam so queue mode, drops, wait behavior, durable persistence, retry, and dead-letter handling are owned by one module.
- Separate transport framing from audit filtering so gnet callback shape, UDP frames, and TCP line buffering sit behind a transport adapter.
- Type Vault socket audit-device setup so callers do not construct raw Vault option maps for common socket audit devices.
- Consolidate integration harness helpers for Vault setup, audit listeners, frame entry, waits, cleanup, and assertions.

## Capabilities

### New Capabilities

- `audit-architecture-seams`: Define the requirements for deeper module seams around configuration assembly, audit filtering, side effects, transport framing, Vault audit-device setup, and integration harnesses.

### Modified Capabilities

- None. This change should preserve existing behavior while reshaping internal interfaces.

## Impact

- Affected code: `cmd/`, `pkg/auditserver/`, `pkg/forwarder/`, `pkg/messaging/`, `pkg/vault/`, and `integration_test.go`.
- Runtime behavior: intended to remain unchanged for UDP/TCP intake, rule matching, logging, forwarding, messaging, async drops, durable retry, and Vault setup payloads.
- Test behavior: tests should move toward explicit module interfaces instead of global Viper state and private field mutation.
- OpenSpec coordination: this change must respect the archived gnet v2 migration decisions and the existing follow-up to migrate `React`-based tests to `OnTraffic`.
