## Context

`vault-audit-filter` receives Vault audit logs over UDP or TCP, evaluates rule expressions, writes matching frames, and optionally forwards or sends messaging side effects. Recent OpenSpec changes added gnet v2 runtime compatibility and TCP audit protocol support. Those changes intentionally preserved behavior and kept `React` as a compatibility shim during migration.

The current implementation is well covered, but some modules are shallow at their public or test-facing interfaces:

- Runtime construction is driven by global Viper state.
- Rule group execution is represented as exported data fields rather than behavior.
- Side-effect queue, durable retry, and dead-letter details leak into tests.
- Transport framing shares a module with audit frame processing.
- Vault socket audit setup exposes map keys that callers must remember.
- Integration tests repeat orchestration logic and timing assumptions.

## Goals

- Preserve existing behavior while changing internal module shape.
- Concentrate configuration defaults, validation, and normalization in one place.
- Give audit frame processing a smaller interface for rule group execution and side-effect submission.
- Keep gnet, UDP, and TCP framing details out of filtering logic.
- Keep Vault socket audit-device schema knowledge inside the Vault package.
- Reduce repeated integration setup and waiting logic.
- Maintain or improve current package coverage for changed files.

## Non-Goals

- Do not change rule expression syntax or matching semantics.
- Do not change default async behavior, including latency-first drop mode.
- Do not introduce a new durable queue technology.
- Do not change user-facing config keys unless a compatibility adapter preserves existing keys.
- Do not remove `React` until the existing OnTraffic parity follow-up is satisfied.
- Do not introduce new dependencies unless a later implementation task justifies one explicitly.

## Decisions

### 1. Use One Umbrella Change With Staged Tasks

The candidates overlap around `auditserver.New`, rule group construction, and tests. A single OpenSpec change avoids duplicated requirements and lets implementation proceed in safe stages. Each stage should be independently verifiable.

### 2. Make Config Assembly the First Stage

The first deepening should be a typed configuration assembly module. Viper should remain an adapter in command startup and tests that intentionally exercise CLI/config behavior. Runtime modules should receive normalized settings rather than reading global state.

This stage unlocks the later work by giving tests and constructors explicit inputs.

### 3. Preserve Existing Runtime Behavior as the Compatibility Target

The goal is module depth, locality, and leverage, not behavior change. Existing behavior around matched/unmatched frames, invalid JSON, log writes, forwarding, messaging, drop counts, durable retry, and Vault setup should be regression-tested before and after each implementation stage.

### 4. Keep Consumer-Owned Interfaces at Real Seams

Interfaces should live where behavior varies for the consuming module. For example, auditserver may consume a small side-effect submission interface, while concrete Slack, webhook, UDP, and file-store adapters remain behind construction or package-specific seams. One adapter does not justify broad interface surface unless tests or runtime behavior truly vary across it.

### 5. Coordinate Transport Work With the Existing React Follow-Up

The archived gnet v2 migration explicitly kept `React` as a temporary compatibility shim. This change may create a transport framing module, but it must not remove `React` until the OnTraffic parity migration has been implemented and verified.

## Module Plan

### Configuration Assembly

Create a module that owns:

- async defaults and validation
- durable retry defaults and validation
- audit protocol normalization
- rule group config decoding
- log file config normalization
- side-effect adapter construction inputs

Command code remains the Viper adapter. Tests that do not exercise Viper should construct typed settings directly.

### Vault Socket Audit Device

Add a typed socket audit-device specification for common setup:

- path
- address
- protocol
- description
- raw logging policy

The Vault package should translate that typed specification to Vault's option map. Existing generic `EnableAuditDevice` can remain for lower-level callers if needed.

### Rule Group Execution

Move rule group behavior behind a deeper module:

- rule matching
- log writing and fallback logger behavior
- payload copy/string preparation
- side-effect request creation

The frame processor should not reason about nil combinations across writer, logger, messenger, and forwarder fields.

### Side-Effect Processor

Create a higher-level module for side effects:

- submit side-effect request
- queue capacity and drop accounting
- wait/drop enqueue mode
- durable save and replay
- retry and dead-letter transitions
- worker lifecycle

File-backed durable storage should remain an adapter behind this module. Tests should be able to exercise retry and store behavior without constructing `AuditServer` internals.

### Transport Framing

Separate gnet and framing concerns from filtering:

- gnet `OnTraffic` adapter
- UDP one-frame reads
- TCP newline-delimited stream buffering
- connection context carryover
- conversion of processing outcomes to gnet actions

The audit frame processor remains focused on parse, match, log, and side-effect submission. `React` remains until the existing parity follow-up allows removal.

### Integration Harness

Consolidate repeated integration helper logic:

- environment defaults
- Vault client creation
- audit device setup and cleanup
- UDP/TCP audit listener setup
- frame delivery into the runtime entry path
- wait/poll assertions instead of fixed sleeps where practical
- log file and forwarding assertions

This harness should stay unexported and test-only.

## Data Flow

1. Command startup reads flags/config through Viper.
2. Config assembly normalizes settings and constructs typed runtime inputs.
3. The audit server is constructed from explicit settings and adapters.
4. Transport adapter receives network bytes and emits complete audit frames.
5. Audit frame processor decodes and evaluates frames.
6. Rule group execution writes logs and creates side-effect requests.
7. Side-effect processor handles async delivery, drops, durable retry, and dead letters.

## Error Handling

- Invalid user configuration should fail in config assembly with contextual errors.
- Invalid audit protocol should keep current command-level failure behavior.
- Invalid audit frames should preserve current parse-error action behavior.
- Rule compilation failures should preserve current logging and skip behavior unless a later task deliberately changes it.
- Side-effect delivery failures should preserve current logging, retry, and dead-letter behavior.
- Vault setup errors should keep contextual wrapping.

## Testing

Each stage should include focused regression coverage before broad verification.

Required final verification:

- `go fmt ./...`
- `go vet ./...`
- `go test -v -race ./...`
- `go test ./... -coverpkg=./... -coverprofile=coverage.out`
- `go tool cover -func=coverage.out`

If integration-related code changes, also run:

- `go test -tags=integration -v -race ./...`

## Risks and Mitigations

- **Risk: broad refactor changes behavior accidentally.** Mitigation: stage the work and preserve existing tests as regression gates.
- **Risk: new seams become hypothetical.** Mitigation: keep interfaces consumer-owned and require at least runtime/test variation before broadening an interface.
- **Risk: transport work conflicts with the existing React migration.** Mitigation: keep `React` until OnTraffic parity is verified.
- **Risk: config assembly becomes a new shallow pass-through.** Mitigation: put defaults, validation, normalization, and typed settings construction behind the module, not just field copying.
- **Risk: integration harness hides important scenario detail.** Mitigation: keep scenario inputs explicit and centralize only repeated orchestration.
