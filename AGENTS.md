# AGENTS.md

Repository-specific guidance for agentic coding assistants working in `vault-audit-filter`.

## Scope and intent

- This is a Go CLI/service that receives Vault audit logs over UDP, applies rule expressions, writes matching events, and optionally forwards/messages side effects.
- Keep changes minimal and local; preserve existing architecture (`cmd/`, `pkg/`, integration tests with `//go:build integration`).
- Prefer correctness and debuggability over clever optimizations.

## Repository map

- `main.go`: binary entrypoint.
- `cmd/`: Cobra command wiring and configuration bootstrap.
- `pkg/auditserver/`: core filtering and async side-effect pipeline.
- `pkg/forwarder/`: UDP forwarding implementation.
- `pkg/messaging/`: Slack and Slack webhook integrations.
- `pkg/vault/`: Vault API client helpers/auth flows.
- `integration_test.go`: integration suite guarded by build tag.

## Toolchain and environment

- Go version: `1.25.x` (see `go.mod` and GitHub Actions workflows).
- CI forces toolchain via: `go env -w GOTOOLCHAIN=go1.25.0+auto`.
- Integration tests expect a running Vault dev server.
- Default local integration env values:
  - `VAULT_ADDR=http://127.0.0.1:8200`
  - `VAULT_TOKEN=root-token`

## Build, lint, and test commands

### Primary commands (from `Makefile`)

- Build: `make build`
- Unit tests: `make test-unit`
- Integration tests: `make test-integration`
- Coverage: `make test-coverage`
- Lint+format gate: `make lint`
- Full local gate: `make lint test build`

### Direct Go equivalents

- Build binary: `go build -o vault-audit-filter .`
- Build all packages: `go build -v ./...`
- Unit tests with race: `go test -v -race ./...`
- Integration tests: `go test -tags=integration -v -race ./...`
- Coverage profile:
  - `go test -coverpkg=./... ./... -race -coverprofile=coverage.out -covermode=atomic`
  - `go tool cover -func=coverage.out`
- Vet: `go vet ./...`
- Format: `go fmt ./...`

### Run a single test (important)

- Single test by name in one package:
  - `go test -v ./pkg/forwarder -run '^TestUDPForwarder_ConcurrentForwarding$'`
- Single subtest pattern:
  - `go test -v ./pkg/auditserver -run 'TestReact_Branches/logger_print_branch_returns_None'`
- Multiple tests by regex in one package:
  - `go test -v ./pkg/auditserver -run 'TestNew_Async.*|TestEnqueueSide_.*'`
- Integration single test:
  - `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root-token go test -tags=integration -v . -run '^TestIntegration_VaultConnection$'`

### Helpful local infra commands

- Start Vault for integration tests: `make docker-up`
- Stop Vault: `make docker-down`
- One-shot integration flow: `make integration`

## CI behavior to mirror locally

- Unit/coverage job runs race-enabled tests across all packages.
- Integration job starts Vault service and runs `-tags=integration` tests.
- Keep local checks aligned with CI to avoid drift.

## Code style guidelines

### Formatting and file structure

- Always run `go fmt ./...` on touched packages/files.
- Keep files gofmt-compliant; do not manually align whitespace.
- Preserve package layout and current directory boundaries.
- Prefer small focused functions; avoid large monolithic handlers.

### Imports

- Rely on gofmt import grouping/sorting.
- Standard library imports first, third-party next, local module imports last.
- Use import aliases only when required (name collisions or established convention, e.g., `json "github.com/bytedance/sonic"`).
- Remove unused imports immediately.

### Types and interfaces

- Prefer concrete types unless an interface improves testability or boundary design.
- Keep interfaces small and behavior-oriented (see `Messenger`, `Forwarder`).
- Define interfaces at consumption boundaries when possible.
- Use typed structs for configuration payloads rather than `map[string]any`, except where external APIs require maps.
- Respect existing zero-value-safe behavior patterns.

### Naming conventions

- Exported identifiers: `PascalCase`; unexported: `camelCase`.
- Keep names explicit and domain-based (`RuleGroupConfig`, `asyncEnqueueTimeout`).
- Acronyms follow Go norms (`URL`, `ID`, `API`, `UDP`).
- Test names: `Test<Subject>_<Scenario>` where practical.

### Error handling

- Never ignore meaningful errors; handle or return them.
- Wrap returned errors with context using `%w` (e.g., `fmt.Errorf("failed to create UDP forwarder: %w", err)`).
- Log errors with structured fields (`"error", err`) using `slog`.
- Avoid `panic` in application paths; return errors upward.
- In tests, use `require.NoError` for setup preconditions and `assert.*` for behavioral checks.

### Logging and observability

- Use structured logging (`log/slog`) in runtime code.
- Keep log messages concise and stable; include key dimensions (rule group, config key, error).
- Do not log secrets/tokens/webhook URLs.

### Concurrency and performance

- Prefer explicit synchronization (`sync.Mutex`, channels, atomics) over implicit assumptions.
- Respect existing async queue/drop/wait/durable semantics in `pkg/auditserver`.
- Avoid unnecessary allocations in hot paths; maintain current pooling/copy semantics unless changing behavior intentionally.
- When changing async behavior, ensure drop metrics and retries remain coherent.

### Configuration and defaults

- Use `viper.SetDefault` for new config keys.
- Validate and normalize user-provided config values with safe fallbacks.
- Keep backward compatibility for existing config fields.

## Testing guidelines

- Prefer table-driven tests for branching logic.
- Keep unit tests deterministic and isolated; avoid external network dependencies unless explicitly integration-tagged.
- For integration coverage, keep `//go:build integration` guard.
- Use `t.TempDir()` for filesystem tests.
- Validate concurrent behavior with synchronization primitives, not long arbitrary sleeps (except where unavoidable).
- When fixing a bug, add or update the smallest regression test that fails before the fix.

## Safety and change boundaries

- Do not introduce new dependencies unless clearly justified.
- Do not mix broad refactors with behavior changes in one patch.
- Preserve existing public behavior unless task explicitly asks for a behavior change.
- Keep secrets out of code, logs, and tests.

## Cursor/Copilot instructions audit

- `.cursor/rules/`: not present in this repository.
- `.cursorrules`: not present in this repository.
- `.github/copilot-instructions.md`: not present in this repository.
- No additional agent rule files were found beyond this `AGENTS.md`.

## Quick pre-PR checklist for agents

- Run: `go fmt ./...`
- Run: `go vet ./...`
- Run: `go test -v -race ./...`
- If integration-related code changed, run: `go test -tags=integration -v -race ./...`
- Summarize what changed, why, and exact verification commands executed.
