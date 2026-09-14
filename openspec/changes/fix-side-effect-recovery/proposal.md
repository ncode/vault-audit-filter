## Why

A failed dead-letter write currently permits deletion of the pending task, and replay can send again after the delivery limit is exhausted. The side-effect processor also retains five mirror pointers into the audit server, spreading state ownership and test setup across both modules.

## What Changes

- Make the durable storage module own the complete, repeatable dead-letter handoff, retaining recoverable work on storage errors.
- Retry failed handoffs automatically using the existing backoff without repeating notification or forwarding.
- Persist a reserved delivery attempt before sending and enforce the delivery limit before replay can send.
- Persist each task's delivery limit at acceptance; legacy records adopt the current limit once before further delivery.
- Preserve terminal failure reasons when known and identify an interrupted final attempt's unknown outcome explicitly.
- Replace pending records safely so a failed write cannot truncate the prior valid record.
- Remove mirrored server state and the five mirror pointers; keep queue state, settings and counters inside the existing processor module.
- **BREAKING behavior correction:** delivery attempts count when reserved, including an attempt interrupted before sending; configuration changes no longer alter existing tasks' limits. Existing configuration keys and the submission interface remain available.

## Capabilities

### New Capabilities

- `durable-side-effect-recovery`: Persisted delivery limits and attempt reservations, safe dead-letter transitions, storage-only retries, and compatible recovery of legacy pending records.

### Modified Capabilities

None of the capabilities currently under `openspec/specs/` describe durable delivery. Async ownership is an internal refactor covered by the design, implementation tasks and behavioral regression checks, rather than a separate new capability.

## Impact

- Runtime and tests: `pkg/auditserver/async.go`, `durable.go`, `server.go`, and the corresponding package tests; documentation of durable behavior and the domain glossary.
- Persistence: extend pending records with the task's delivery limit and outcome information needed for recovery; continue reading legacy records. An older binary does not enforce the new recovery contract.
- Dependencies: retain the existing file adapter, test adapters, queue mechanism and public interfaces; add no dependency or configuration key.
- Scope: preserve non-durable delivery, task-level notification/forwarding semantics, payload copying, drop/wait behavior, defaults and zero-worker support. Transport migration and shutdown redesign are separate work.
- Spec coordination: this follow-up intentionally supersedes the durable-equivalence scenario in the completed, unarchived architecture change. That earlier capability is absent from the main specs; this new capability is the successor contract for durable recovery. Its older compatibility scenario must be reconciled when those specs are eventually synchronized, without changing unrelated requirements.
