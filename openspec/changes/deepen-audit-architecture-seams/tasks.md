## 1. Baseline and Guardrails

- [x] 1.1 Run baseline `go test -v -race ./...`.
- [x] 1.2 Run baseline `go test ./... -coverpkg=./... -coverprofile=coverage.out` and `go tool cover -func=coverage.out`.
- [x] 1.3 Capture focused behavior checks for invalid JSON, no-match frames, matched frames, log writing, forwarding, messaging, async drops, durable retry, TCP framing, and Vault setup payloads.
- [x] 1.4 Confirm the existing OnTraffic parity follow-up remains the owner of `React` shim removal.

## 2. Configuration Assembly

- [x] 2.1 Introduce typed runtime settings for audit server construction.
- [x] 2.2 Move async defaults and validation into config assembly.
- [x] 2.3 Move durable retry defaults and validation into config assembly.
- [x] 2.4 Move audit protocol normalization into one config path used by command startup and audit server construction.
- [x] 2.5 Keep Viper usage in command/config adapter code and remove runtime reads from `pkg/auditserver`.
- [x] 2.6 Update unit tests to construct typed settings directly where Viper behavior is not under test.

## 3. Vault Socket Audit Device

- [x] 3.1 Add a typed Vault socket audit-device specification.
- [x] 3.2 Translate the typed specification to Vault socket audit options inside `pkg/vault`.
- [x] 3.3 Update setup command code to use the typed socket audit-device path.
- [x] 3.4 Update integration tests to avoid constructing raw socket audit option maps where they exercise standard socket audit setup.

## 4. Rule Group Execution

- [x] 4.1 Introduce a rule group execution module that owns match, write, payload preparation, and side-effect request creation.
- [x] 4.2 Reduce frame handler knowledge of rule group internals and nil field combinations.
- [x] 4.3 Preserve existing behavior for empty rules, runtime rule errors, invalid compiled rules, writer errors, and logger fallback.
- [x] 4.4 Update tests to exercise rule group execution through its interface.

## 5. Side-Effect Processor

- [x] 5.1 Introduce a side-effect processor module with a higher-level submit interface.
- [x] 5.2 Move queue mode, wait/drop behavior, drop accounting, and worker lifecycle behind the processor.
- [x] 5.3 Keep file-backed durable storage as an adapter behind the processor.
- [x] 5.4 Preserve durable save, replay, retry, and dead-letter behavior.
- [x] 5.5 Update tests to avoid constructing `AuditServer` solely to test side-effect queue internals.

## 6. Transport Framing

- [x] 6.1 Introduce a transport adapter module for gnet callback and frame extraction.
- [x] 6.2 Move UDP one-frame and TCP newline-delimited buffering behavior behind the transport adapter.
- [x] 6.3 Preserve existing parse-error, no-match, and match action outcomes.
- [x] 6.4 Keep `React` compatibility until the OnTraffic parity migration has passed.
- [x] 6.5 Update tests to share frame-processing fixtures with the existing OnTraffic parity follow-up where practical.

## 7. Integration Harness

- [x] 7.1 Create unexported integration helpers for Vault client setup, audit device setup/cleanup, UDP/TCP listeners, and frame delivery.
- [x] 7.2 Replace repeated fixed sleeps with polling helpers where practical.
- [x] 7.3 Consolidate repeated log file, forwarding, and operation filtering assertions without hiding scenario-specific inputs.
- [x] 7.4 Ensure integration tests remain guarded by `//go:build integration`.

## 8. Documentation and Verification

- [x] 8.1 Update README configuration docs if constructor/config assembly changes alter documented defaults or examples.
- [x] 8.2 Run `go fmt ./...`.
- [x] 8.3 Run `go vet ./...`.
- [x] 8.4 Run `go test -v -race ./...`.
- [x] 8.5 Run coverage commands and close misses/partials in changed packages.
- [x] 8.6 If integration paths changed, run `go test -tags=integration -v -race ./...`.
