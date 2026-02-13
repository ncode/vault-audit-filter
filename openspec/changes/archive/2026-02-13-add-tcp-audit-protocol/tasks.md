## 1. Configuration and Payload Wiring

- [x] 1.1 Add `vault.audit_protocol` config key and validation with default `udp`.
- [x] 1.2 Wire protocol value into Vault setup payload as `socket_type`.
- [x] 1.3 Validate CLI/config precedence and error behavior for invalid values.

## 2. Listener and Parsing Implementation

- [x] 2.1 Build audit server listen URL from configured protocol (`udp://` or `tcp://`).
- [x] 2.2 Implement stream-safe line framing in `pkg/auditserver` with carryover buffering.
- [x] 2.3 Ensure each complete JSON line is processed independently without changing rule outcome semantics.

## 3. Tests

- [x] 3.1 Add/expand unit tests for config validation and invalid protocol error handling.
- [x] 3.2 Add unit tests for setup payload protocol values and listener URL protocol selection.
- [x] 3.3 Add unit tests for newline-framed TCP stream parsing (multi-line reads, split reads, malformed lines).

## 4. Documentation and Verification

- [x] 4.1 Update example config/docs to include `vault.audit_protocol` and defaults.
- [x] 4.2 Run `go test` for touched packages and full `go test ./...`.
- [x] 4.3 Run `go vet ./...` and `go fmt ./...` before finalizing.
