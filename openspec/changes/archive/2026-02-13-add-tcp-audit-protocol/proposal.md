## Why

The current audit server assumes a packet-per-event network model and always configures Vault socket audit as UDP, which makes TCP-based deployments impossible without manual out-of-band changes. Teams running Vault in environments where TCP transport is required (for reliable delivery, proxy compatibility, or firewall policy) cannot use this tool as-is.

This change adds explicit protocol configuration so users can choose TCP or UDP for inbound listener setup and Vault audit export, while preserving UDP as the default and keeping all existing behavior for side effects and rule matching unchanged.

## What Changes

- Add `vault.audit_protocol` configuration with allowed values `udp` and `tcp` (default `udp`), including startup validation.
- Update `setup` command behavior to send the selected protocol as `socket_type` in Vault's audit-socket enable payload.
- Update `auditServer` startup to listen using the configured protocol (`udp://` or `tcp://`) instead of hardcoded UDP.
- Introduce stream-safe JSON framing in `pkg/auditserver` so TCP reads can process multiple events in one read and partial events split across reads.
- Add regression coverage for protocol selection and TCP framing behavior to preserve previous UDP behavior.

## Capabilities

### New Capabilities
- `tcp-audit-protocol`: Provide configurable Vault audit ingestion transport (`udp` or `tcp`) with protocol-aware listener setup and protocol-safe payload parsing.

### Modified Capabilities
- _None_

## Impact

- Command/config surface: new `vault.audit_protocol` option in CLI/config.
- Vault setup payload: new `socket_type` values passed through from configuration.
- Audit server network startup and frame parser in `pkg/auditserver`.
- Unit tests in `cmd` and `pkg/auditserver` updated with protocol and stream-framing cases.
