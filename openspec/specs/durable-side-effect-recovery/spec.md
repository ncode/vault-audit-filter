# durable-side-effect-recovery Specification

## Purpose
Keep accepted durable side-effect tasks recoverable while enforcing their delivery limits across process restarts, and complete dead-letter storage without repeating exhausted delivery.

## Requirements

### Requirement: Fixed delivery limit per task

The system SHALL persist the configured delivery limit when accepting a durable side-effect task. Later configuration changes SHALL NOT alter that task's limit, including during queue saturation, retry or recovery.

#### Scenario: Configuration changes after acceptance

- **WHEN** a task accepted with a delivery limit of three is recovered while the configured limit is five
- **THEN** the task SHALL retain its limit of three
- **AND** newly accepted tasks SHALL use the configured limit of five

#### Scenario: Legacy task adopts a limit once

- **WHEN** a legacy pending task has no stored delivery limit
- **THEN** the system SHALL adopt the current configured limit without resetting the existing attempt count
- **AND** it SHALL persist that limit before permitting delivery
- **AND** subsequent recovery SHALL retain the adopted limit even if configuration changes

#### Scenario: Legacy limit cannot be persisted

- **WHEN** persistence of a legacy task's adopted limit fails
- **THEN** the system SHALL report the storage failure and SHALL NOT deliver the task
- **AND** it SHALL retain the recoverable pending record and retry the persistence operation using the existing backoff

### Requirement: Persisted reservation before delivery

The system SHALL count and persist each delivery attempt before sending any of that attempt's notification or forwarding work. It SHALL check the task's stored delivery limit before reserving another attempt. Queue operations and storage retries SHALL NOT themselves consume additional delivery attempts.

#### Scenario: Attempt is reserved before either destination is contacted

- **WHEN** a durable task has remaining delivery allowance
- **THEN** its attempt count SHALL be incremented and successfully persisted before its notification or forwarding begins
- **AND** notification and forwarding configured on the same task SHALL share that delivery attempt

#### Scenario: Reservation persistence fails

- **WHEN** an attempt reservation cannot be persisted
- **THEN** neither notification nor forwarding SHALL occur
- **AND** retrying the persistence operation SHALL NOT allocate another attempt for that same unsent reservation

#### Scenario: Final reservation survives interruption before sending

- **WHEN** a process is interrupted after persisting its final permitted attempt but before sending
- **THEN** that attempt SHALL remain consumed on recovery
- **AND** the recovered task SHALL receive no further delivery attempts

#### Scenario: A failed attempt has remaining allowance

- **WHEN** notification or forwarding fails and the task still has remaining delivery attempts
- **THEN** another delivery attempt SHALL be scheduled using the existing retry backoff
- **AND** that attempt SHALL require its own persisted reservation

### Requirement: Exhaustion prevents redelivery

An exhausted task SHALL only undergo dead-letter handoff or its storage retries. This restriction SHALL apply before delivery during recovery and SHALL remain in force regardless of current configuration.

#### Scenario: Task has reached its stored limit

- **WHEN** a recovered task's reserved attempt count equals or exceeds its stored delivery limit
- **THEN** the system SHALL perform no notification or forwarding for that task
- **AND** it SHALL complete or retry the task's dead-letter handoff

#### Scenario: Interrupted final attempt has no recorded outcome

- **WHEN** a final reserved attempt is recovered without a recorded outcome
- **THEN** its dead-letter reason SHALL identify that the final outcome is unknown
- **AND** a previous attempt's failure SHALL NOT be represented as the final attempt's outcome

#### Scenario: Final failure is known

- **WHEN** a final delivery failure is recorded and later recovered
- **THEN** its dead-letter task SHALL retain the recorded failure reason

### Requirement: Recoverable dead-letter handoff

The system SHALL retain recoverable pending work until the dead-letter record is successfully stored. Repeating a partially completed handoff SHALL preserve the dead-letter task and SHALL NOT cause delivery.

#### Scenario: Dead-letter write fails

- **WHEN** a dead-letter record cannot be stored
- **THEN** the pending task SHALL remain recoverable
- **AND** the failure SHALL be reported without treating the task as successfully archived

#### Scenario: Pending removal fails after dead-letter storage

- **WHEN** a valid dead-letter record exists but its pending copy cannot be removed
- **THEN** the valid dead-letter record SHALL be retained
- **AND** subsequent retry or recovery SHALL perform cleanup without notification or forwarding
- **AND** an unknown-outcome fallback SHALL NOT overwrite the existing recorded reason

#### Scenario: Legacy pending work overlaps a dead letter

- **WHEN** recovery finds both a pending task and a valid dead-letter record for the same task, including a legacy pending record
- **THEN** the dead-letter record SHALL establish that delivery has stopped regardless of the pending attempt count
- **AND** the pending copy SHALL only be eligible for cleanup

### Requirement: Automatic storage recovery

Failed dead-letter storage or cleanup SHALL retry automatically in the running process using the existing retry backoff. These retries SHALL NOT consume delivery attempts, invoke delivery, or increment the queue's drop count for recoverable durable work.

#### Scenario: Storage becomes available again

- **WHEN** dead-letter storage initially fails and subsequently recovers
- **THEN** the running process SHALL complete the handoff without requiring a restart
- **AND** no notification or forwarding SHALL occur during those storage retries

#### Scenario: Storage remains unavailable

- **WHEN** repeated dead-letter storage or cleanup attempts fail
- **THEN** the task SHALL remain recoverable and retries SHALL continue at the configured backoff
- **AND** the system SHALL report failures without logging audit payloads or credentials

#### Scenario: Cleanup after successful delivery fails

- **WHEN** pending removal fails after successful delivery
- **THEN** the failure SHALL be reported
- **AND** in-process cleanup retries SHALL perform only storage work

### Requirement: Safe pending-record updates

An unsuccessful update SHALL NOT destroy the previous valid pending record. Recovery SHALL consider only completely published task records and SHALL NOT silently reset invalid persisted delivery accounting.

#### Scenario: Updating a reservation is interrupted

- **WHEN** an update is interrupted before the new pending record is completely published
- **THEN** the previous valid pending record SHALL remain readable
- **AND** no delivery SHALL have been permitted on the basis of the unpublished reservation

#### Scenario: Temporary write remains after interruption

- **WHEN** recovery encounters an incomplete temporary write alongside valid pending records
- **THEN** the temporary write SHALL NOT be delivered or prevent recovery of the valid records

#### Scenario: Persisted accounting is invalid

- **WHEN** a pending record contains a negative attempt count or an explicitly invalid stored delivery limit
- **THEN** the system SHALL report the invalid record and retain it without delivery
- **AND** it SHALL NOT treat the invalid limit as an absent legacy limit or reset the attempt count to grant new allowance

### Requirement: Preserve unaffected side-effect behavior

The recovery correction and internal ownership refactor SHALL preserve existing configuration keys, defaults, non-durable delivery, enqueue wait/drop behavior, zero-worker support and task-level notification/forwarding semantics.

#### Scenario: Non-durable queue remains saturated

- **WHEN** the non-durable queue is full
- **THEN** drop mode SHALL retain non-blocking rejection and drop accounting
- **AND** wait mode SHALL retain its configured timeout behavior

#### Scenario: Workers are disabled

- **WHEN** zero side-effect workers are configured
- **THEN** automatic delivery and dead-letter processing SHALL remain disabled
- **AND** accepted durable work SHALL remain available for later processing

#### Scenario: Only one destination succeeds

- **WHEN** a task configures both notification and forwarding and only one succeeds
- **THEN** the attempt SHALL count once for the task
- **AND** any permitted retry SHALL retain the existing behavior of attempting both destinations
