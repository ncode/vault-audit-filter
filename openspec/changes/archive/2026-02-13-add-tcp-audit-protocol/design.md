## Context

Current behavior always initializes Vault socket auditing as UDP and starts the server with a hardcoded `udp://` listener. The server currently treats each read from gnet as one complete frame and decodes directly, which is suitable for datagram-like input but not robust for TCP stream behavior.

The repository already has a gnet-based UDP transport and unit tests centered on `React([]byte)` behavior. To add TCP support reliably, both transport initialization and parsing must change together while preserving existing behavior and defaults.

## Goals / Non-Goals

**Goals:**
- Add `vault.audit_protocol` with default `udp` and allow `tcp`.
- Propagate protocol to both Vault setup (`socket_type`) and runtime listener URL (`udp://` vs `tcp://`).
- Parse incoming audit lines as newline-delimited JSON records across read boundaries.
- Keep existing UDP rule-evaluation and forwarding behavior unchanged.
- Keep changes minimal and validate through unit tests.

**Non-Goals:**
- No migration of protocol semantics to other output transports.
- No custom framing formats beyond newline-delimited JSON records.
- No changes to metrics API shape or alerting paths.

## Decisions

1. **Config + validation in `cmd` layer**: add `vault.audit_protocol` as a string with allowed values `udp` and `tcp`. This follows existing configuration validation patterns and preserves backward compatibility by defaulting to `udp`.
2. **Single protocol source of truth**: reuse the config value in both `setup` and `auditServer` startup to ensure emitted Vault sink config and listener scheme stay aligned.
   - Alternative considered: separate inbound/outbound protocol keys, rejected to avoid unnecessary config surface and extra migration risk.
3. **Buffered line parser for transport frames**: in the audit server, accumulate incoming bytes and split on `\n`, keeping any trailing partial record in a carryover buffer.
   - Alternative considered: keeping raw frame assumptions and adding only conditional handling, rejected because it is still fragile for TCP message coalescing and fragmentation.
4. **`json.Decoder` per line, preserving error path**: parse each complete line independently and keep existing behavior for invalid JSON (error + existing side effect semantics).

## Risks / Trade-offs

- **Risk**: TCP packets containing very large events could increase memory pressure if buffer grows without bounds. → Mitigation: enforce/track a practical maximum frame length if needed in a follow-up hardening change; current behavior remains conservative as existing event sizes in this project are expected small.
- **Risk**: Users may rely on non-newline-terminated events. → Mitigation: maintain strict line-delimited parsing and document contract; reject malformed/incomplete final buffers as existing processing invalid-event behavior.
- **Risk**: Defaulting to UDP may hide misconfiguration in TCP-only environments. → Mitigation: explicit validation plus explicit value in generated setup payload and clear docs.
- **Risk**: New branch parsing code affects both protocol paths. → Mitigation: covered with focused unit tests for multi-record and fragmented reads.

## Migration Plan

1. Add the new config key with defaults and validation.
2. Update setup and server URL construction to use selected protocol.
3. Add parser buffering and streaming tests.
4. Run unit/integration-style targeted tests, then merge.

Rollback is low risk: revert one commit to restore UDP defaults and line parser.

## Open Questions

- None.
