## Why

The current gnet v2 migration keeps `React` as a compatibility shim for existing tests and benchmarks. We need a dedicated follow-up to move tests to `OnTraffic` so the shim can be removed safely.

## What Changes

- Migrate unit, benchmark, and integration entry points from direct `React` invocation to v2-native `OnTraffic`-oriented coverage patterns.
- Add parity verification criteria to ensure behavior is unchanged across invalid payload, no-match, and match scenarios.
- Remove the `React` compatibility shim only after parity verification passes.

## Capabilities

### New Capabilities
- `ontraffic-test-parity-migration`: Define requirements for replacing `React`-based test entry points with `OnTraffic`-aligned tests while preserving behavioral parity.

### Modified Capabilities
- None.

## Impact

- Affected code: audit server unit tests, benchmark harness, and integration wiring used for direct frame entrypoints.
- Risk control: explicit parity checks gate shim removal.
