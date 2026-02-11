## 1. Baseline and migration seam

- [x] 1.1 Run focused baseline tests for current `React` behavior in `pkg/auditserver` and `cmd`.
- [x] 1.2 Extract internal `handleFrame(frame []byte) gnet.Action` from existing `React` logic in `pkg/auditserver/server.go`.
- [x] 1.3 Keep `React(frame []byte, c gnet.Conn)` as a compatibility wrapper that delegates to `handleFrame`.
- [x] 1.4 Re-run focused `pkg/auditserver` tests to verify no behavior changes after seam extraction.

## 2. Runtime migration to gnet v2

- [x] 2.1 Update runtime imports from `github.com/panjf2000/gnet` to `github.com/panjf2000/gnet/v2` in `pkg/auditserver/server.go` and `cmd/auditServer.go`.
- [x] 2.2 Replace embedded engine type with `*gnet.BuiltinEventEngine` in `AuditServer`.
- [x] 2.3 Add `OnTraffic(c gnet.Conn) gnet.Action` adapter that reads frame bytes and calls `handleFrame`.
- [x] 2.4 Replace `gnet.Serve(...)` with `gnet.Run(...)` in `cmd/auditServer.go`.

## 3. Tests and dependency cleanup

- [x] 3.1 Keep existing unit/benchmark/integration direct `React` entrypoint usage working without broad test rewrites.
- [x] 3.2 Update only test mocks/signatures required to compile with gnet v2 imports.
- [x] 3.3 Remove `github.com/panjf2000/gnet` (v1) dependency from `go.mod` once no v1 imports remain.
- [x] 3.4 Run module tidy/update to keep `go.mod`/`go.sum` consistent after dependency cleanup.

## 4. Verification

- [x] 4.1 Run `go fmt ./...`.
- [x] 4.2 Run `go vet ./...`.
- [x] 4.3 Run `go test -v -race ./pkg/auditserver ./cmd`.
- [x] 4.4 Run `go test -v -race ./...`.

## 5. Follow-up tracking

- [x] 5.1 Create a follow-up change to migrate tests from `React` to `OnTraffic`.
- [x] 5.2 In that follow-up, remove `React` compatibility shim only after parity verification passes.
