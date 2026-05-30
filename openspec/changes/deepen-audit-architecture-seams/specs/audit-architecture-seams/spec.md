## ADDED Requirements

### Requirement: Explicit configuration assembly

The system SHALL assemble runtime configuration through a typed configuration module before constructing audit runtime modules.

#### Scenario: Runtime construction avoids global Viper

- **WHEN** audit server runtime modules are constructed outside command/config adapter tests
- **THEN** they SHALL receive typed settings rather than reading global Viper state

#### Scenario: Defaults and validation are centralized

- **WHEN** async, durable retry, or audit protocol settings are omitted or invalid
- **THEN** defaulting and validation SHALL occur in one configuration assembly path with contextual errors or documented fallbacks

#### Scenario: Existing configuration remains compatible

- **WHEN** users provide existing config keys such as `rule_groups`, `async.queue_size`, `async.workers`, or `vault.audit_protocol`
- **THEN** those keys SHALL continue to map to equivalent runtime behavior

### Requirement: Typed Vault socket audit-device setup

The system SHALL provide a typed path for standard Vault socket audit-device setup.

#### Scenario: Setup command enables socket audit

- **WHEN** the setup command enables a Vault socket audit device
- **THEN** command code SHALL pass a typed socket audit-device specification rather than manually constructing Vault socket option maps

#### Scenario: Vault option map creation is localized

- **WHEN** Vault socket audit options are sent to Vault
- **THEN** Vault socket keys such as `address`, `socket_type`, and `log_raw` SHALL be produced inside the Vault package or its adapter module

#### Scenario: Existing generic audit enablement remains available

- **WHEN** lower-level callers need non-socket or custom audit device setup
- **THEN** the existing generic enablement path MAY remain available with current behavior

### Requirement: Deep rule group execution seam

The system SHALL concentrate rule group matching, log writing, payload preparation, and side-effect request creation behind a rule group execution module.

#### Scenario: Frame processing evaluates groups

- **WHEN** a decoded audit frame is processed
- **THEN** frame processing SHALL not need to inspect writer, logger, messenger, or forwarder nil combinations directly

#### Scenario: Empty rules preserve match-all behavior

- **WHEN** a rule group has no compiled rules
- **THEN** that group SHALL match audit frames as it does today

#### Scenario: Rule runtime errors preserve skip behavior

- **WHEN** a compiled rule returns an evaluation error
- **THEN** evaluation SHALL continue to preserve existing skip/non-match behavior

#### Scenario: Log write behavior remains stable

- **WHEN** a matched rule group has a writer, logger fallback, or write error
- **THEN** log writing and error logging SHALL preserve existing behavior

### Requirement: Side-effect processor seam

The system SHALL own async side-effect delivery through a side-effect processor module with a higher-level submit interface.

#### Scenario: Drop mode stays non-blocking

- **WHEN** side-effect enqueue mode is drop and the queue is full
- **THEN** submission SHALL preserve current non-blocking drop behavior and drop accounting

#### Scenario: Wait mode respects timeout

- **WHEN** side-effect enqueue mode is wait and the queue remains full
- **THEN** submission SHALL wait up to the configured timeout and then preserve current drop or durable retry behavior

#### Scenario: Durable retry behavior remains stable

- **WHEN** durable side effects are enabled and delivery fails
- **THEN** persistence, replay, retry, max-attempt, and dead-letter behavior SHALL remain equivalent to current behavior

#### Scenario: Side-effect adapters remain substitutable

- **WHEN** messaging or forwarding behavior is tested
- **THEN** tests SHALL be able to substitute adapters without mutating unrelated audit server internals

### Requirement: Transport framing seam

The system SHALL separate network transport framing from audit frame filtering behavior.

#### Scenario: UDP frame delivery

- **WHEN** UDP traffic is received
- **THEN** the transport adapter SHALL deliver the datagram payload as one audit frame with current behavior

#### Scenario: TCP stream delivery

- **WHEN** TCP traffic is received with multiple complete newline-delimited records or split records
- **THEN** the transport adapter SHALL preserve current line buffering and carryover behavior

#### Scenario: Action outcomes remain compatible

- **WHEN** audit frame processing sees invalid JSON, no matching rule group, or at least one matching rule group
- **THEN** returned gnet action outcomes SHALL preserve current behavior

#### Scenario: React compatibility follows existing migration

- **WHEN** transport framing is refactored
- **THEN** `React` SHALL remain available until the existing OnTraffic parity migration verifies removal criteria

### Requirement: Integration harness locality

The integration suite SHALL concentrate repeated Vault, listener, wait, cleanup, and assertion orchestration in unexported test helpers.

#### Scenario: Vault audit integration setup

- **WHEN** an integration test needs Vault client setup and audit-device lifecycle management
- **THEN** it SHALL use shared helper logic for repeated setup and cleanup

#### Scenario: Listener and frame delivery setup

- **WHEN** an integration test needs UDP or TCP audit delivery
- **THEN** it SHALL use shared listener and frame-delivery helpers while keeping scenario-specific inputs explicit

#### Scenario: Waiting for async effects

- **WHEN** an integration test waits for logs or forwarding side effects
- **THEN** it SHOULD use polling helpers instead of fixed sleeps where practical

#### Scenario: Integration tests remain guarded

- **WHEN** integration harness code is added or changed
- **THEN** integration tests SHALL remain guarded by `//go:build integration`
