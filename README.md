# Vault Audit Filter

[![Go](https://github.com/ncode/vault-audit-filter/actions/workflows/go.yml/badge.svg)](https://github.com/ncode/vault-audit-filter/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ncode/vault-audit-filter)](https://goreportcard.com/report/github.com/ncode/vault-audit-filter)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![codecov](https://codecov.io/gh/ncode/vault-audit-filter/graph/badge.svg?token=PTW9OYF19R)](https://codecov.io/gh/ncode/vault-audit-filter)

`vault-audit-filter` is designed to filter and log HashiCorp Vault audit logs based on configurable rules. It provides fine-grained control over how Vault audit events are processed and categorized, allowing you to capture critical events while reducing noise from routine operations.

## Features

- **Configurable Rule-Based Filtering**: Define rules to match specific audit events, such as read, write, delete, or specific paths in Vault.
- **Multiple Rule Groups**: Organize rules into groups and log them to separate files.
- **Dynamic Logging**: Log audit events to specified files with log rotation and size limits.
- **Supports Multiple Operations**: Filters common Vault operations, including KV operations, metadata updates, and deletion events.
- **Performance-Oriented**: Built with `gnet` to handle high concurrency.
- **Flexible Forwarding**: Forward filtered audit logs to specified UDP addresses for further processing or monitoring.
- **Messaging Integration**: Send notifications about matched audit logs to messaging platforms like Slack.

## Table of Contents

- [Getting Started](#getting-started)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Getting Started

These instructions will help you set up and run `vault-audit-filter` on your local machine.

### Prerequisites

- **Go**: Ensure you have Go 1.25.5 or later installed. You can download it here: <https://golang.org/dl/>
- **Vault**: You should have HashiCorp Vault installed and configured. Instructions can be found here: <https://www.vaultproject.io/docs/install>

### Installation

Clone the repository:

    git clone https://github.com/ncode/vault-audit-filter.git
    cd vault-audit-filter

### Build the Project

To build the binary:

    go build -o vault-audit-filter .

### Running the Application

Once you have built the project, you can run the `vault-audit-filter` executable:

    ./vault-audit-filter --config config.yaml

## Configuration

`vault-audit-filter` uses a YAML-based configuration file that allows you to define rule groups, specify logging files, configure Vault settings, set up forwarding options, and configure messaging integration.

### Sample Configuration (`config.yaml`)

    vault:
      address: "http://127.0.0.1:8200"
      token: "your-vault-token"
      audit_path: "/vault-audit-filter"
      audit_address: "127.0.0.1:1269"
      audit_protocol: "udp"
      audit_description: "Vault Audit Filter Device"

    async:
      queue_size: 20
      workers: 2
      timeout: 5s

    rule_groups:
      - name: "normal_operations"
        rules:
          - 'Request.Operation in ["read", "update"] && Request.Path startsWith "secret/data/" && Auth.PolicyResults.Allowed == true'
        log_file:
          file_path: "/var/log/vault_normal_operations.log"
          max_size: 100      # Max size in MB
          max_backups: 5     # Max number of backup files
          max_age: 30        # Max age in days
          compress: true     # Compress rotated files
        forwarding:
          enabled: true
          address: "127.0.0.1:9001"
        messaging:
          type: "slack_webhook"
          webhook_url: "https://your-slack-instance.com/hooks/your-webhook-id"

      - name: "critical_events"
        rules:
          - 'Request.Operation == "delete" && Auth.PolicyResults.Allowed == true'
          - 'Request.Path startsWith "secret/metadata/" && Auth.PolicyResults.Allowed == true'
        log_file:
          file_path: "/var/log/vault_critical_events.log"
          max_size: 100
          max_backups: 5
          max_age: 30
          compress: true
        forwarding:
          enabled: true
          address: "127.0.0.1:9002"
        messaging:
          type: "slack"
          url: "https://slack.com/api/"
          token: "your-bot-token"
          channel: "your-channel-id"

### Configuration Parameters

- **Vault Settings**:
  - `vault.address`: The address of your Vault instance.
  - `vault.token`: Vault token for authentication.
  - `vault.audit_path`: The path for Vault's audit device.
  - `vault.audit_address`: The address for receiving audit logs.
  - `vault.audit_protocol`: Socket transport for Vault audit device (`udp` or `tcp`, default `udp`).
  - `vault.audit_description`: Description for the Vault audit device.

- **Rule Groups**:
  - `rule_groups.name`: The name of the rule group.
  - `rule_groups.rules`: A list of expressions using `expr` to define rules for audit log filtering.
  - `log_file.file_path`: The file path where matching logs will be written.
  - `log_file.max_size`: The maximum size of the log file in MB before rotation.
  - `log_file.max_backups`: The number of backup logs to keep.
  - `log_file.max_age`: The maximum number of days to retain logs.
  - `log_file.compress`: Whether to compress the old log files.
  - `forwarding.enabled`: Whether to enable forwarding for this rule group.
  - `forwarding.address`: The UDP address to forward matching audit logs to.
  - `messaging.type`: The type of messaging integration ("slack" or "slack_webhook").
  - `messaging.webhook_url`: The webhook URL for Slack (when using "slack_webhook" type).
  - `messaging.url`: The Slack API base URL (when using "slack" type).
  - `messaging.token`: The bot token for Slack (when using "slack" type).
  - `messaging.channel`: The channel ID for Slack messages (when using "slack" type).

  - **Async Settings**:
  - `async.queue_size`: Bounded queue length for async side effects (drop on full).
  - `async.workers`: Number of async side-effect workers (`0` disables worker execution).
  - `async.timeout`: Timeout for Slack API/webhook and forwarding operations.

### Async Tuning Profiles

Use these as baseline profiles and tune from there:

| Profile | `async.queue_size` | `async.workers` | `async.timeout` | Expected Behavior |
| --- | ---: | ---: | --- | --- |
| Latency-first (default) | 20 | 2 | 5s | Lowest request latency; highest drop risk during bursts |
| Balanced | 256 | 8 | 5s | Low request latency with lower drop rate than default |
| Throughput-biased | 1024 | 16 | 5s | Low request latency with significantly fewer drops; higher CPU/memory usage |

Representative stress-test results (2000 requests, concurrency 64, slow downstream side effects):

| Config | Downstream Delay | Request Avg | Request P95 | Inferred Drops |
| --- | ---: | ---: | ---: | ---: |
| Sync (`main`) | 20ms | 21.0ms | 21.4ms | 0 |
| Async `q=64,w=2` | 20ms | 0.30ms | 1.06ms | 1934/2000 |
| Async `q=256,w=8` | 20ms | 0.34ms | 1.39ms | 1736/2000 |
| Async `q=1024,w=16` | 20ms | 0.37ms | 1.80ms | 960/2000 |

Interpretation:
- Current async design is appropriate when request-path latency protection is the top priority.
- If side-effect delivery reliability is required, increase queue/workers and monitor drops, or move to a durable retry design.

### Performance Findings and Decision

Performance findings from the latest comparison are:
- Synchronous mode (`main`) preserves side-effect delivery in the test scenario, but request latency tracks downstream delay (about 21ms average at 20ms downstream delay).
- Asynchronous mode keeps request latency low (sub-millisecond average in measured scenarios), but can drop a large fraction of side effects during bursts depending on queue/workers settings.

Caveats:
- The numbers above come from synthetic stress tests (2000 requests, concurrency 64) and are intended as directional guidance.
- Real production behavior depends on traffic burst shape, downstream service health, and host resource limits.

Current decision:
- Operate in latency-first async mode by default.
- Treat side effects as best-effort unless deployment requirements explicitly demand stronger delivery guarantees.

When durable/retry work is needed:
- Side-effect drops remain sustained and unacceptable after tuning `async.workers` and `async.queue_size`.
- Audit/operational requirements require stronger guarantees than best-effort delivery.

Follow-up options:
1. Add bounded blocking enqueue mode to trade some request latency for fewer drops.
2. Add durable retry and dead-letter flow for stronger side-effect delivery guarantees.
3. Re-run workload-specific tuning tests and adjust profile recommendations.

Tuning checklist:
1. Start with `Latency-first` or `Balanced`.
2. Monitor side-effect drop count and request tail latency.
3. If drops are sustained and unacceptable, raise `async.workers` first, then `async.queue_size`.
4. If request tail latency regresses, reduce workers or move to a balanced profile.
5. If drops remain unacceptable, adopt durable retry architecture rather than unbounded tuning.

### Rule Syntax

Rules are written using the `expr` language, a simple and safe expression language for Go. Rules can be based on the following properties of audit logs:

- `Request.Operation`: The type of operation (`read`, `update`, `delete`, etc.).
- `Request.Path`: The Vault path being accessed.
- `Auth.PolicyResults.Allowed`: Whether the operation was allowed.

**Example Rule**:

  'Request.Operation == "update" && Request.Path startsWith "secret/data/" && Auth.PolicyResults.Allowed == true'

## Usage

`vault-audit-filter` provides two subcommands:

### Setup Vault Audit Device

Configure Vault to send audit logs to this service:

```bash
./vault-audit-filter setup --config config.yaml
```

### Start the Audit Server

Start the audit server to receive and filter Vault audit logs:

```bash
./vault-audit-filter auditServer --config config.yaml
```

### Command-Line Options

**Global flags:**

- `--config`: Specify the path to the configuration file (default is `$HOME/.vault-audit-filter.yaml`).
- `--vault.address`: Vault server address (default: `http://127.0.0.1:8200`).
- `--vault.token`: Vault authentication token.
- `--vault.audit_path`: Path for the Vault audit device (default: `/vault-audit-filter`).
- `--vault.audit_address`: Address for receiving audit logs (default: `127.0.0.1:1269`).
- `--vault.audit_protocol`: Audit socket transport (`udp` or `tcp`, default: `udp`).
- `--vault.audit_description`: Description for the Vault audit device.

### Environment Variables

You can also define environment variables to override configuration file values. For example:

```bash
$ export VAULT_ADDRESS="http://127.0.0.1:8200"
$ export VAULT_TOKEN="your-vault-token"
```

For integration tests that run Vault in Docker, set `AUDIT_HOST=host.docker.internal` so the containerized Vault can reach the host-side TCP listener used by integration tests.

## Testing

To run the test suite for `vault-audit-filter`, use the following command:

```bash
go test -v ./...
```

For running tests with race condition detection:

```bash
go test -race -v ./...
```

To run a specific test, such as the concurrent forwarding test:

```bash
go test -v -run TestUDPForwarder_ConcurrentForwarding ./pkg/forwarder
```

To generate a test coverage report:

```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Development

For development purposes, you can use the provided Makefile located at `configs/development/Makefile` to build and run the project using Docker and Docker Compose. This is how I test my changes and have a playground of sorts.

## Contributing

We welcome contributions from the community! 
Before submitting a pull request, ensure that:

- The code compiles without errors.
- All tests pass.
- Your changes are well-documented.
- You've added or updated tests to cover your changes.

## License

This project is licensed under the Apache License, Version 2.0. See the `LICENSE` file for details.
