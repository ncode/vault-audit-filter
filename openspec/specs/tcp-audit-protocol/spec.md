# tcp-audit-protocol Specification

## Purpose
TBD - created by archiving change add-tcp-audit-protocol. Update Purpose after archive.
## Requirements
### Requirement: Configurable audit protocol
The system SHALL provide a `vault.audit_protocol` configuration value with allowed values `udp` and `tcp`.

#### Scenario: Default protocol
- **WHEN** `vault.audit_protocol` is omitted
- **THEN** the effective protocol SHALL be `udp`

#### Scenario: Invalid protocol value
- **WHEN** `vault.audit_protocol` is set to any value other than `udp` or `tcp`
- **THEN** startup SHALL fail with a validation error

### Requirement: Protocol-aware Vault setup
The system SHALL send the configured protocol as `socket_type` in Vault audit-socket enable requests.

#### Scenario: TCP setup
- **WHEN** `vault.audit_protocol` is set to `tcp`
- **THEN** the `setup` payload SHALL include `socket_type: tcp`

### Requirement: Protocol-aware audit listener
The system SHALL bind the audit server listener URL using the configured protocol.

#### Scenario: TCP listener setup
- **WHEN** `vault.audit_protocol` is set to `tcp`
- **THEN** the listener URI SHALL use `tcp://<host>:<port>`

### Requirement: Stream-safe protocol parsing
The system SHALL parse incoming audit data as newline-delimited JSON records from a continuous byte stream.

#### Scenario: Multiple events in one read
- **WHEN** one network read contains multiple complete JSON lines
- **THEN** each complete line SHALL be parsed and processed independently

#### Scenario: Split event across reads
- **WHEN** a JSON event is split across multiple reads
- **THEN** the parser SHALL buffer incomplete bytes and process the event only after the line delimiter is received

