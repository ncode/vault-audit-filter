## Why

The project currently declares both `github.com/panjf2000/gnet` (v1) and `github.com/panjf2000/gnet/v2`, while the runtime still uses v1 APIs. This split increases maintenance risk and blocks a clean upgrade path, so we should standardize on gnet v2 now while preserving existing audit filtering behavior.

## What Changes

- Migrate audit server runtime wiring from gnet v1 APIs (`Serve`, `EventServer`, `React`) to gnet v2 APIs (`Run`, `BuiltinEventEngine`, `OnTraffic`).
- Introduce a compatibility seam for frame processing so existing tests, benchmarks, and integration code paths that call `React` can continue to work during migration.
- Remove direct dependence on gnet v1 from module dependencies once runtime and tests compile and pass with v2.
- Preserve existing behavior for matched/unmatched audit events, JSON parse failures, side-effect enqueueing, and logging outputs.

## Capabilities

### New Capabilities
- `gnet-v2-runtime-compatibility`: Define the requirement that the audit server runs on gnet v2 while maintaining backward-compatible frame-processing semantics during migration.

### Modified Capabilities
- None.

## Impact

- Affected code: `cmd/auditServer.go`, `pkg/auditserver/server.go`, and gnet-related tests/benchmarks/integration entry points.
- Dependencies: consolidates networking runtime to `github.com/panjf2000/gnet/v2` and enables removal of v1 dependency.
- Runtime/API surface: internal event callback wiring changes, but user-visible filtering and side-effect behavior is intended to remain unchanged.
