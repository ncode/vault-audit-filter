## Context

The audit server currently depends on gnet v1 runtime APIs (`Serve`, `EventServer`, `React`) while `go.mod` also includes gnet v2. This creates ambiguity in dependency ownership and increases maintenance overhead. The server is latency-sensitive, processes UDP-delivered Vault audit payloads, and has established behavior around filtering, side effects, and log writing that must remain stable.

Constraints:
- Preserve current filter semantics and `gnet.Action` outcomes for parse failures and non-matches.
- Keep change scope local to gnet wiring and callback adaptation.
- Avoid broad test rewrites in the same change.

Stakeholders:
- Operators running `auditServer` in production-like environments.
- Maintainers relying on existing unit/integration test suites for regression safety.

## Goals / Non-Goals

**Goals:**
- Standardize runtime networking integration on `github.com/panjf2000/gnet/v2`.
- Introduce a stable frame-processing seam so business logic is independent from gnet callback shape.
- Maintain compatibility for existing tests/benchmarks/integration paths that currently invoke `React` directly.
- Remove gnet v1 dependency from module requirements once verification is complete.

**Non-Goals:**
- Re-architecting async side-effect pipeline, retry, or durable queue behavior.
- Refactoring unrelated audit parsing/rule evaluation logic.
- Rewriting all tests to use v2 callback interfaces in this change.

## Decisions

1. **Add an internal frame handler seam (`handleFrame`) and keep `React` as a compatibility wrapper**
   - Rationale: preserves existing call sites (`server.React(frame, nil)`) in tests, benchmarks, and integration helpers while isolating gnet API migration to adapter methods.
   - Alternatives considered:
     - Remove `React` immediately and migrate all tests now: rejected due to high churn and risk of mixing behavioral and structural changes.
     - Keep direct logic only in `OnTraffic`: rejected because it would tightly couple business logic to connection I/O and reduce testability.

2. **Adopt v2 event model with `BuiltinEventEngine` + `OnTraffic` + `Run`**
   - Rationale: aligns with supported gnet v2 API surface and removes dual-version ambiguity.
   - Alternatives considered:
     - Continue on v1 until later: rejected because v2 is already declared in dependencies and current split state is fragile.

3. **Keep behavioral semantics unchanged during migration**
   - Rationale: this change is infrastructural. Existing behavior (including close/none action outcomes and side-effect dispatch semantics) is the compatibility target.
   - Alternatives considered:
     - Opportunistic behavior adjustments during migration: rejected to keep regression risk low.

4. **Use incremental dependency cleanup after compile+test verification**
   - Rationale: remove v1 from `go.mod` only after runtime and tests pass on v2, preventing premature dependency breakage.

## Risks / Trade-offs

- **[Risk] UDP payload lifetime differs in v2 callback flow** -> Mitigation: ensure payload bytes are copied before async use, preserving existing defensive copy behavior.
- **[Risk] Interface/method mismatches in test mocks when imports move to v2** -> Mitigation: avoid unnecessary mock surface changes by retaining `React`-driven tests where possible.
- **[Trade-off] Temporary dual API surface (`OnTraffic` + `React` shim)** -> Mitigation: document `React` as transitional and schedule later cleanup once migration stabilizes.
- **[Risk] Subtle action semantics drift (`Close` vs `None`)** -> Mitigation: run focused regression tests around parse errors, no-match paths, and matched paths.

## Migration Plan

1. Extract `handleFrame(frame []byte) gnet.Action` from existing `React` logic in `pkg/auditserver/server.go`.
2. Keep `React(frame []byte, c gnet.Conn)` as a wrapper calling `handleFrame` (compatibility path).
3. Switch runtime imports and wiring to gnet v2:
   - `github.com/panjf2000/gnet/v2`
   - `*gnet.BuiltinEventEngine`
   - `gnet.Run(...)` in `cmd/auditServer.go`.
4. Add `OnTraffic(c gnet.Conn) gnet.Action` adapter that reads frame bytes and delegates to `handleFrame`.
5. Run verification (`go fmt`, `go vet`, focused tests, then broader test run).
6. Remove gnet v1 requirement from `go.mod`/`go.sum` if no remaining imports.

Rollback strategy:
- Revert the migration commit(s), restoring v1 imports/wiring and previous callback path.

## Open Questions

- None for this change.

Decisions captured:
- Keep `React` as an internal compatibility shim for this migration and do not add deprecation comments in this change.
- Create a follow-up change to migrate test entry points from `React` to `OnTraffic`, then remove the shim after parity is verified.
