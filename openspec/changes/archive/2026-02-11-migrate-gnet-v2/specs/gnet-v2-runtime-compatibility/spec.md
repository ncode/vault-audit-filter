## ADDED Requirements

### Requirement: Audit server SHALL run on gnet v2 runtime APIs
The audit server runtime SHALL use `github.com/panjf2000/gnet/v2` and SHALL start the UDP server using v2 engine entrypoints.

#### Scenario: Start audit server command
- **WHEN** the `auditServer` command starts the network engine
- **THEN** it uses gnet v2 runtime APIs (`Run` and v2 event engine types) rather than gnet v1 APIs

### Requirement: Frame processing SHALL remain behavior-compatible during migration
The audit server SHALL preserve existing frame-processing outcomes while migrating callback wiring, including matched/unmatched event handling and invalid JSON handling.

#### Scenario: Invalid audit payload
- **WHEN** a received payload cannot be parsed as valid audit JSON
- **THEN** the server returns the same close action outcome used before migration

#### Scenario: No matching rule group
- **WHEN** a valid audit payload matches no configured rule group
- **THEN** the server returns the same close action outcome used before migration

#### Scenario: Matching rule group
- **WHEN** a valid audit payload matches at least one configured rule group
- **THEN** the server returns the same non-close action outcome used before migration and continues side-effect processing

### Requirement: Migration SHALL provide a temporary compatibility shim for direct frame entrypoints
During this migration change, the server SHALL retain a direct frame-processing compatibility entrypoint used by existing tests and benchmarks, while routing runtime traffic through the v2 callback.

#### Scenario: Existing tests call compatibility entrypoint
- **WHEN** unit, benchmark, or integration tests invoke the direct frame entrypoint
- **THEN** they execute the same underlying frame-processing logic used by the v2 runtime callback
