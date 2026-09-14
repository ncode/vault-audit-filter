## Context

See `proposal.md` for the two findings and `specs/durable-side-effect-recovery/spec.md` for the recovery contract. Domain terms are defined in the root `CONTEXT.md`.

The current processor sends before checking the attempt limit. It records increments after failed delivery and unconditionally deletes pending work after attempting a dead-letter write. Pending records contain an attempt count but no fixed delivery limit or final outcome. The file adapter writes directly over existing pending files.

The audit server duplicates processor settings, queue references, store references and counters. Five mirror pointers and a repeated test-construction helper preserve that coupling despite the processor already exposing submission and drop observation.

## Goals / Non-Goals

**Goals:**

- Make persisted accounting sufficient to decide whether recovery can deliver without relying on the previous process's memory.
- Keep transition ordering and file replacement inside the storage module, with retry scheduling inside the processor.
- Remove duplicate ownership while preserving the current module interface and real adapter seams.
- Verify behavior through observable delivery, pending records, dead letters and drop counts.

**Non-Goals:**

- Exactly-once remote delivery, separate acknowledgement tracking for each destination, or whole-machine power-loss guarantees.
- A new queue technology, retry framework, public interface, configuration key, transport migration or shutdown redesign.

## Decisions

### 1. Persist a delivery limit with each accepted task

Add a stored delivery limit to the pending representation and retain it in the processor's task representation. Use the configured limit only for new tasks and legacy records that genuinely omit the field. Persist a legacy record's adopted limit before permitting delivery; preserve its existing attempt count.

Distinguish absence from an explicitly invalid value when decoding. Negative counts and invalid explicit limits must produce an error and must not gain new delivery allowance. Counts at or above a valid limit represent exhausted work, including legacy records after limit adoption.

**Alternative rejected:** applying the current runtime limit on every replay could reopen delivery after a configuration increase and makes a task's budget depend on restart timing.

### 2. Reserve attempts before delivery

Check exhaustion before contacting either delivery adapter. For eligible work, persist the next reserved count before sending. Both configured destinations share one task-level attempt, preserving existing partial-success behavior.

A failed reservation write permits no send. Schedule persistence recovery using the existing backoff without repeatedly consuming attempts for the same unsent reservation. Queue saturation and queue retries do not allocate attempts.

After restart, the persisted count is authoritative. A final reservation already consumes the last opportunity even if interruption occurred before the send. A fresh in-process reservation may perform its authorized send; replaying that same persisted final reservation may only complete the dead-letter handoff.

**Alternative rejected:** incrementing after failure lets an interruption erase an attempted send from the budget. The accepted tradeoff is that a crash before a send can consume an unused opportunity.

### 3. Preserve outcome meaning without expanding delivery guarantees

Retain the final failure reason when it can be recorded. An outcome from an earlier attempt must not masquerade as the outcome of a newly reserved attempt; clear or distinguish stale outcome information when reserving. If recovery observes the final reserved attempt without its outcome, use an explicit interrupted-attempt/unknown-outcome reason.

The reserved count and stored limit provide the exhaustion decision; a general workflow framework is unnecessary. A valid existing dead-letter record also establishes terminal work, even when an overlapping legacy pending record has a lower count. Preserve its recorded reason during cleanup.

Successful delivery retains existing pending removal. Report removal failures and retry in-process cleanup without invoking either delivery adapter. No exactly-once claim is made for an interrupted successful delivery whose outcome was not durably recorded.

**Alternative rejected:** adding independent notification and forwarding acknowledgement histories would change task semantics and expand the scope beyond the selected findings.

### 4. Deepen the existing storage interface

Keep the consumer's existing `Save`, `Delete`, `MoveToDeadLetter` and `Pending` seam. Make `MoveToDeadLetter` own the complete operation: publish a valid dead-letter record, then remove pending work, reporting either failure. Remove the caller's unconditional follow-up `Delete`.

The file adapter must support a repeated handoff after either stage. A valid dead letter must not be overwritten with a less informative unknown-outcome fallback. Recovery of overlapping pending/dead-letter records must expose cleanup-only work to the processor, including legacy overlaps, so a pending deletion failure can be retried without delivery.

Replace direct overwrites with a small private atomic-file replacement path: write a temporary file in the same directory, finish and close it successfully, then publish it by replacement. Preserve the existing restrictive file permissions. A failed pre-publication update leaves the previous complete record usable. Replay ignores this adapter's incomplete temporary writes; actual malformed pending records still report errors rather than disappearing.

The file adapter owns filesystem details and idempotency; it does not own retry timers or delivery decisions. This is a real seam with both file and test adapters. Its depth comes from removing ordering obligations from callers, improving locality for persistence failures and leverage for recovery tests.

**Alternatives rejected:** only guarding the existing delete fixes one symptom but leaves transition rules in the caller; introducing another storage technology adds an unnecessary migration.

### 5. Retry storage work without re-entering delivery

Reuse the existing retry backoff and scheduling mechanism for persistence failures. Keep the operation being retried explicit enough that dead-letter retries, cleanup retries and reservation-write retries cannot be interpreted as another delivery attempt. Do not add a second queue framework.

Retain recoverable work and report failures. Durable queue saturation continues to preserve tasks without increasing non-durable drop metrics. Exhausted replay goes straight to handoff; no notification or forwarding occurs on that path. Preserve zero-worker behavior and worker startup before replay.

**Alternative rejected:** passing all storage failures through an ordinary delivery retry would repeat sends or consume extra reservations; requiring a restart for storage recovery contradicts the agreed automatic recovery behavior.

### 6. Finish processor state ownership

Delete mirror fields from processor configuration and implementation, then remove the mirrored audit-server fields and their wiring. Keep the queue, atomics, task sequence, normalized processor settings and storage reference in the processor. Construction may create adapters locally and pass them into the processor; the audit server retains its processor reference and existing rule-group adapter resolver.

Keep submission and drop observation as the test surface. Replace mirror-specific assertions and duplicated attachment wiring with processor behavior checks. Configuration tests should check normalized settings or effective behavior instead of server copies. Preserve zero-worker support, default values, task-ID sequencing and payload ownership.

**Alternative rejected:** retaining mirror compatibility preserves no public behavior; the mirrors are private and used by constructor wiring and package tests. A new facade would add another shallow module instead of deleting the coupling.

## Risks / Trade-offs

- **An interruption can consume an unsent attempt** → This is the agreed accounting rule; explicitly test an interrupted final reservation and document the unknown-outcome dead letter.
- **Nonfinal retries may repeat a previously successful destination** → Preserve existing task-level semantics and test partial success; do not promise exactly-once delivery.
- **A failed persistence update could corrupt accounting** → Publish complete records atomically, validate stored values, and test preservation of the prior record on write failure.
- **A partially completed handoff could lose its reason or trigger another send** → Preserve existing dead letters and route overlapping records to storage-only cleanup.
- **Retry scheduling could bypass queue semantics or zero-worker behavior** → Exercise worker-disabled, saturated-queue and storage-retry paths through existing processor tests.
- **Older binaries can disregard the new budget and replay rules** → Continue accepting legacy records on upgrade, but document that downgrade replay does not preserve this contract.

## Migration Plan

1. Add focused regression checks for the loss-of-work bug and the agreed accounting/recovery rules. Verify each behavioral correction fails before its implementation.
2. Implement the durable record extension, safe file updates, complete handoff and processor recovery rules using the existing adapters.
3. Remove async mirrors after the corrected behavior is protected by tests; replace mirror assertions with observable outcomes.
4. Document attempt reservation, fixed limits, legacy adoption, storage-only retries and the accepted interruption tradeoff. Run the repository formatting, vet, race and changed-path coverage gates.
5. Roll out with the existing pending directory; migrate each legacy record on recovery before delivery. Changing configuration affects only newly accepted tasks. Downgrade requires treating this recovery guarantee as unavailable and preserving pending data for a compatible reader; do not automatically rewrite records to emulate the old behavior.

### Spec synchronization coordination

The earlier completed change introduced `audit-architecture-seams` only as a pending delta; it is not a canonical capability yet. Do not invent a `MODIFIED` delta against a nonexistent main spec, archive that change implicitly, or reopen its completed implementation tasks.

When synchronizing the earlier capability, reconcile its `Side-effect processor seam` requirement: replace the scenario `Durable retry behavior remains stable` with `Durable recovery follows the recovery contract`, requiring failures and replay to follow `durable-side-effect-recovery`. Preserve its drop, wait and adapter-substitution scenarios and all unrelated requirements. This is an explicit supersession of the old behavior-preservation constraint, not a request to reproduce the faulty terminal transition.
