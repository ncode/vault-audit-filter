## 1. Establish the regression baseline

- [x] 1.1 Use a toolchain compatible with `go.mod`; run `go test -race ./pkg/auditserver` and retain existing delivery, queue, retry and replay checks as the behavioral baseline.
- [x] 1.2 Add the smallest failing regression for dead-letter persistence failure: pending work remains recoverable and its removal is not treated as successful when archival fails. Keep test data and evidence free of credentials and operational identifiers.

## 2. Make durable records safe to update and recover

- [x] 2.1 Add focused record tests for stored delivery limits, legacy limit adoption, invalid accounting, and preservation of existing attempt counts. Confirm the new contract is not satisfied before implementing it.
- [x] 2.2 Extend the persisted and in-memory task representations with fixed delivery limits and necessary outcome information; distinguish an omitted legacy limit from an invalid explicit value.
- [x] 2.3 Add failure/interruption checks for pending-record replacement and leftover temporary writes, then replace direct overwrites with safe publication inside the file adapter while preserving file permissions and malformed-record reporting.
- [x] 2.4 Add file-adapter checks for failed dead-letter writes, failed pending removal, repeated handoffs and legacy pending/dead-letter overlap; make the existing handoff own publication and pending removal, preserving an already recorded reason and exposing overlaps as cleanup-only work.

## 3. Enforce the recovery contract in the processor

- [x] 3.1 Add failing processor checks that neither delivery adapter runs before reservation persistence succeeds and that persistence retries do not allocate extra attempts for the same unsent reservation.
- [x] 3.2 Capture and persist each new task's configured limit at acceptance; adopt and persist missing legacy limits before delivery without resetting counts. Preserve those limits through queue saturation and enqueue retries.
- [x] 3.3 Move attempt accounting before delivery, check exhaustion before reserving, and preserve one task-level attempt when both notification and forwarding are configured. Retry reservation persistence with the existing backoff without sending on failure.
- [x] 3.4 Add recovery checks using a fresh processor and persisted records: an interrupted final reservation receives no further sends, configuration changes preserve the original limit, and legacy adoption remains fixed across later recovery.
- [x] 3.5 Implement exhaustion checks before replay delivery and preserve final outcome meaning: retain recorded failures, distinguish an unknown interrupted outcome, and prevent previous-attempt errors from being mistaken for the final result.
- [x] 3.6 Add checks for storage failure followed by recovery, persistent storage failure and successful-delivery cleanup failure; assert storage-only retries perform no notification or forwarding and consume no new delivery attempts.
- [x] 3.7 Remove the processor's unconditional delete after handoff. Retry failed dead-letter persistence, overlapping-record cleanup and successful-delivery cleanup as storage work using the existing backoff; report failures without exposing payloads or credentials.
- [x] 3.8 Verify partial destination success, retry exhaustion, durable queue saturation, non-durable drop/wait behavior and zero-worker support through observable processor outcomes.

## 4. Remove async state mirroring

- [x] 4.1 Remove the five mirror pointers and branches from processor configuration and implementation; retain processor-owned queue state, settings, drop counters and task sequencing.
- [x] 4.2 Remove mirrored audit-server fields and constructor wiring, retaining normalized local construction inputs, the processor reference, the existing adapter resolver and worker startup before replay.
- [x] 4.3 Delete mirror-specific assertions and simplify repeated test attachment wiring. Keep submission and drop observation as the test surface; verify effective settings, defaults, zero-worker support, payload ownership and delivery behavior without adding a public observation interface.

## 5. Document and verify the completed change

- [x] 5.1 Update durable behavior documentation using `CONTEXT.md`: reserved attempts, fixed task limits, legacy migration, automatic storage-only retries and the accepted interrupted-attempt tradeoff. Include the downgrade limitation and preserve the spec-synchronization coordination note.
- [x] 5.2 Run `go fmt ./...`, `go vet ./...`, `go test -race ./pkg/auditserver`, `go test -v -race ./...`, and `go build ./...`; address failures caused by this change.
- [x] 5.3 Run `go test ./... -coverpkg=./... -coverprofile=coverage.out` and `go tool cover -func=coverage.out`; inspect changed paths and close uncovered behavior or partial branches with focused regression checks. Keep coverage output out of the change.
- [x] 5.4 If integration wiring or integration behavior changes during implementation, run `go test -tags=integration -v -race ./...` against the local test environment; otherwise retain the current integration scope.
- [x] 5.5 Run `openspec validate fix-side-effect-recovery --strict`, review the final diff for scope and private information, and report the exact verification results without raw operational evidence.

## Verification results

Initially completed with Go 1.26.5 (compatible with the then-current module requirements),
`GOPROXY=off`, and a temporary build cache. All commands below passed:

```sh
go fmt ./...
go vet ./...
go test -race ./pkg/auditserver
go test -v -race ./...
go build ./...
go test ./... -coverpkg=./... -coverprofile=coverage.out
go tool cover -func=coverage.out
OPENSPEC_TELEMETRY=0 DO_NOT_TRACK=1 openspec validate fix-side-effect-recovery --strict
```

- Regression tests first reproduced deletion after failed archival, lost recovery
  metadata, unsafe record replacement, delivery before reservation, changed
  limits after recovery, and repeated delivery during storage retries.
- Coverage: 97.9% repository statements; 100% in each changed production file
  (`async.go`, `durable.go`, `server.go`), with no uncovered statement blocks.
  Recovery scenarios also exercise both delivery destinations, repeated storage
  failures, legacy migration, interrupted reservations and queue saturation.
- File-error tests passed under the race detector, including failed writes,
  closes and publication. Faults avoid relying on filesystem permission denial.
- Integration setup and transport behavior were unchanged; the integration-tagged
  suite was not required for this change.
- Reviewed the implementation, tests and documentation for scope and private
  information. Coverage output and raw verification logs are excluded.
- The spec-synchronization coordination note in `design.md` remains applicable;
  neither this change nor the earlier architecture change was archived.

### Go 1.27.1 follow-up validation

After upgrading Go and dependencies, formatting, vet, the full race suite,
module verification and strict change validation passed again. The full
integration suite also passed against an isolated local test service:

```sh
go test -tags=integration -v -race ./...
go mod verify
go mod tidy -diff
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

The vulnerability scan found no vulnerabilities. Native and Linux/amd64 builds
passed. Coverage on Go 1.27.1 is 98.2% overall and remains 100% in all three
changed production files. Temporary test infrastructure was removed afterward.
