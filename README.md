[![Go Report Card](https://goreportcard.com/badge/github.com/ncode/vault-audit-filter)](https://goreportcard.com/report/github.com/ncode/vault-audit-filter)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![codecov](https://codecov.io/gh/ncode/vault-audit-filter/graph/badge.svg?token=PTW9OYF19R)](https://codecov.io/gh/ncode/vault-audit-filter)

# Vault Audit Filter

`vault-audit-filter` is a Go-based tool designed to filter and log HashiCorp Vault audit logs based on configurable rules. It provides fine-grained control over how Vault audit events are processed and categorized, allowing you to capture critical events while reducing noise from routine operations.

## Features

- **Configurable Rule-Based Filtering**: Define rules to match specific audit events, such as read, write, delete, or specific paths in Vault.
- **Multiple Rule Groups**: Organize rules into groups and log them to separate files.
- **Dynamic Logging**: Log audit events to specified files with log rotation and size limits.
- **Supports Multiple Operations**: Filters common Vault operations, including KV operations, metadata updates, and deletion events.
- **Performance-Oriented**: Built with `gnet` to handle high concurrency.
- **Flexible Forwarding**: Forward filtered audit logs to specified UDP addresses for further processing or monitoring.
- **Messaging Integration**: Send notifications about matched audit logs to messaging platforms like Mattermost.

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

- **Go**: Ensure you have Go 1.22.3 or later installed. You can download it here: <https://golang.org/dl/>
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
      audit_description: "Vault Audit Filter Device"

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
          type: "mattermost_webhook"
          webhook_url: "https://your-mattermost-instance.com/hooks/your-webhook-id"

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
          type: "mattermost"
          url: "https://your-mattermost-instance.com"
          token: "your-bot-token"
          channel: "your-channel-id"

### Configuration Parameters

- **Vault Settings**:
  - `vault.address`: The address of your Vault instance.
  - `vault.token`: Vault token for authentication.
  - `vault.audit_path`: The path for Vault's audit device.
  - `vault.audit_address`: The address for receiving audit logs.
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
  - `messaging.type`: The type of messaging integration ("mattermost" or "mattermost_webhook").
  - `messaging.webhook_url`: The webhook URL for Mattermost (when using "mattermost_webhook" type).
  - `messaging.url`: The Mattermost server URL (when using "mattermost" type).
  - `messaging.token`: The bot token for Mattermost (when using "mattermost" type).
  - `messaging.channel`: The channel ID for Mattermost messages (when using "mattermost" type).

### Rule Syntax

Rules are written using the `expr` language, a simple and safe expression language for Go. Rules can be based on the following properties of audit logs:

- `Request.Operation`: The type of operation (`read`, `update`, `delete`, etc.).
- `Request.Path`: The Vault path being accessed.
- `Auth.PolicyResults.Allowed`: Whether the operation was allowed.

**Example Rule**:

  'Request.Operation == "update" && Request.Path startsWith "secret/data/" && Auth.PolicyResults.Allowed == true'

## Usage

To run `vault-audit-filter` with your configuration file, use:

```bash
$ ./vault-audit-filter --config config.yaml
```

### Command-Line Options

- `--config`: Specify the path to the configuration file (default is `config.yaml`).
- `--log-level`: Set the logging level (`debug`, `info`, `warn`, `error`).

### Environment Variables

You can also define environment variables to override configuration file values. For example:

```bash
$ export VAULT_ADDRESS="http://127.0.0.1:8200"
$ export VAULT_TOKEN="your-vault-token"
```

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
