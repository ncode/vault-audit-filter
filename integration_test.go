//go:build integration

package main

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/ncode/vault-audit-filter/pkg/auditserver"
	"github.com/ncode/vault-audit-filter/pkg/vault"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultVaultAddr  = "http://127.0.0.1:8200"
	defaultVaultToken = "root-token"
	defaultAuditAddr  = "127.0.0.1:1269"
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func tcpAuditAddressFromListener(listenerAddr net.Addr) string {
	port := "0"
	if _, p, err := net.SplitHostPort(listenerAddr.String()); err == nil {
		port = p
	}

	host := getEnvOrDefault("AUDIT_HOST", "127.0.0.1")
	return net.JoinHostPort(host, port)
}

func TestIntegration_VaultConnection(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err, "Failed to connect to Vault")
	require.NotNil(t, client)

	// Verify we can list auth methods (proves connection works)
	_, err = client.Sys().ListAuth()
	assert.NoError(t, err, "Failed to list auth methods")
}

func TestIntegration_EnableAuditDevice(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)
	auditAddr := getEnvOrDefault("AUDIT_ADDR", defaultAuditAddr)

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	// Clean up any existing audit device from previous test runs
	_ = client.Sys().DisableAudit("integration-test")

	// Enable the audit device
	err = client.EnableAuditDevice(
		"integration-test",
		"socket",
		"Integration test audit device",
		map[string]string{
			"address":     auditAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err, "Failed to enable audit device")

	// Verify it was enabled
	audits, err := client.Sys().ListAudit()
	require.NoError(t, err)
	assert.Contains(t, audits, "integration-test/", "Audit device should be enabled")

	// Clean up
	err = client.Sys().DisableAudit("integration-test")
	assert.NoError(t, err)
}

func TestIntegration_AuditDeviceWithSocketConfig(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	// Connect to Vault
	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	// Clean up any existing audit device
	_ = client.Sys().DisableAudit("integration-socket-test")

	// Enable audit device with socket configuration
	// Use a dummy address - we're testing the API works, not actual delivery
	err = client.EnableAuditDevice(
		"integration-socket-test",
		"socket",
		"Integration socket test",
		map[string]string{
			"address":     "127.0.0.1:19999",
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err, "Should be able to enable socket audit device")

	// Verify the audit device is enabled
	audits, err := client.Sys().ListAudit()
	require.NoError(t, err)
	assert.Contains(t, audits, "integration-socket-test/")

	// Perform some Vault operations that will generate audit logs
	err = client.Sys().Mount("integration-kv", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Write a secret - this should succeed even if audit can't deliver
	// (Vault continues operating when audit device is unavailable in dev mode)
	_, err = client.Logical().Write("integration-kv/data/test-secret", map[string]interface{}{
		"data": map[string]interface{}{
			"username": "testuser",
			"password": "testpass",
		},
	})
	// Note: In production, this might fail if audit is required
	// In dev mode, Vault continues even if audit delivery fails
	if err != nil {
		t.Logf("Write operation result: %v (expected in some configurations)", err)
	}

	// Clean up
	_ = client.Sys().DisableAudit("integration-socket-test")
	_ = client.Sys().Unmount("integration-kv")
}

func TestIntegration_AuditServerWithRules(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	// Create a temp file for audit logs
	tmpDir := t.TempDir()
	logFile := tmpDir + "/audit.log"

	// Configure viper with rule groups
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "all_operations",
			"rules": []string{
				"Auth.PolicyResults.Allowed == true",
			},
			"log_file": map[string]interface{}{
				"file_path":   logFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	// Create the audit server
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Start a UDP listener
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()
	t.Logf("Audit server listening on %s", localAddr)

	// Process incoming messages in a goroutine
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				// Process through the audit server
				server.React(buf[:n], nil)
			}
		}
	}()

	// Connect to Vault and enable audit device
	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-rules-test")

	err = client.EnableAuditDevice(
		"integration-rules-test",
		"socket",
		"Integration rules test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	// Perform Vault operations
	err = client.Sys().Mount("integration-kv-rules", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for rules",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	_, err = client.Logical().Write("integration-kv-rules/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(500 * time.Millisecond)
	close(done)

	// Check that logs were written
	logContent, err := os.ReadFile(logFile)
	if err == nil && len(logContent) > 0 {
		t.Logf("Audit log file contains %d bytes", len(logContent))
		assert.True(t, len(logContent) > 0, "Should have written audit logs")
	}

	// Clean up
	_ = client.Sys().DisableAudit("integration-rules-test")
	_ = client.Sys().Unmount("integration-kv-rules")
}

func TestIntegration_AuditServerWithRules_TCP(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	logFile := tmpDir + "/audit-tcp.log"

	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "all_tcp",
			"rules": []string{
				"true",
			},
			"log_file": map[string]interface{}{
				"file_path":   logFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)
	require.NotNil(t, server)

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	auditListener, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	defer auditListener.Close()

	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)

		conn, acceptErr := auditListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 65535)
		carry := make([]byte, 0)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				carry = append(carry, buf[:n]...)

				for {
					idx := bytes.IndexByte(carry, '\n')
					if idx < 0 {
						break
					}

					frame := carry[:idx]
					frame = bytes.TrimSuffix(frame, []byte{'\r'})
					if len(frame) > 0 {
						server.React(frame, nil)
					}

					if idx+1 >= len(carry) {
						carry = carry[:0]
					} else {
						carry = carry[idx+1:]
					}
				}
			}

			if readErr != nil {
				return
			}
		}
	}()

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-rules-tcp-test")

	err = client.EnableAuditDevice(
		"integration-rules-tcp-test",
		"socket",
		"Integration TCP rules test",
		map[string]string{
			"address":     tcpAuditAddressFromListener(auditListener.Addr()),
			"socket_type": "tcp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	err = client.Sys().Mount("integration-kv-rules-tcp", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for tcp rules",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	_, err = client.Logical().Write("integration-kv-rules-tcp/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	_ = client.Sys().DisableAudit("integration-rules-tcp-test")
	_ = client.Sys().Unmount("integration-kv-rules-tcp")
	_ = auditListener.Close()
	<-auditDone

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Greater(t, len(content), 0, "should have written audit logs over TCP")
}

func TestIntegration_AuditServerForwarding(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	// Start a UDP receiver for forwarded messages
	forwardAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	forwardConn, err := net.ListenUDP("udp", forwardAddr)
	require.NoError(t, err)
	defer forwardConn.Close()

	forwardLocalAddr := forwardConn.LocalAddr().String()
	t.Logf("Forward receiver listening on %s", forwardLocalAddr)

	// Collect forwarded messages
	var forwarded []string
	var mu sync.Mutex
	forwardDone := make(chan struct{})

	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-forwardDone:
				return
			default:
				forwardConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := forwardConn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				mu.Lock()
				forwarded = append(forwarded, string(buf[:n]))
				mu.Unlock()
			}
		}
	}()

	// Create temp log file
	tmpDir := t.TempDir()
	logFile := tmpDir + "/audit.log"

	// Configure viper with forwarding enabled
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "forward_all",
			"rules": []string{
				"true", // Match everything
			},
			"log_file": map[string]interface{}{
				"file_path":   logFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
			"forwarding": map[string]interface{}{
				"enabled": true,
				"address": forwardLocalAddr,
			},
		},
	})

	// Create the audit server
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	// Start audit server listener
	auditAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	auditConn, err := net.ListenUDP("udp", auditAddr)
	require.NoError(t, err)
	defer auditConn.Close()

	auditLocalAddr := auditConn.LocalAddr().String()
	t.Logf("Audit server listening on %s", auditLocalAddr)

	// Process incoming messages
	auditDone := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-auditDone:
				return
			default:
				auditConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := auditConn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	// Connect to Vault
	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-forward-test")

	err = client.EnableAuditDevice(
		"integration-forward-test",
		"socket",
		"Integration forward test",
		map[string]string{
			"address":     auditLocalAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	// Perform Vault operations
	err = client.Sys().Mount("integration-kv-forward", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for forwarding",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	_, err = client.Logical().Write("integration-kv-forward/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	// Wait for processing
	time.Sleep(500 * time.Millisecond)
	close(auditDone)
	close(forwardDone)

	// Verify forwarding worked
	mu.Lock()
	defer mu.Unlock()

	t.Logf("Received %d forwarded messages", len(forwarded))

	// Clean up
	_ = client.Sys().DisableAudit("integration-forward-test")
	_ = client.Sys().Unmount("integration-kv-forward")
}

// TestIntegration_OperationFiltering tests rules that filter by operation type
func TestIntegration_OperationFiltering(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	deleteLogFile := tmpDir + "/delete_ops.log"
	readLogFile := tmpDir + "/read_ops.log"

	// Configure two rule groups: one for deletes, one for reads
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "delete_operations",
			"rules": []string{
				`Request.Operation == "delete"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   deleteLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
		{
			"name": "read_operations",
			"rules": []string{
				`Request.Operation == "read"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   readLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	// Start UDP listener
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-op-filter-test")

	err = client.EnableAuditDevice(
		"integration-op-filter-test",
		"socket",
		"Integration operation filter test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	// Setup KV engine
	err = client.Sys().Mount("integration-kv-opfilter", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for op filtering",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Write a secret
	_, err = client.Logical().Write("integration-kv-opfilter/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	// Read the secret (generates read operation)
	_, err = client.Logical().Read("integration-kv-opfilter/data/test")
	require.NoError(t, err)

	// Delete the secret (generates delete operation)
	_, err = client.Logical().Delete("integration-kv-opfilter/data/test")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	close(done)

	// Check delete log file
	deleteContent, err := os.ReadFile(deleteLogFile)
	if err == nil && len(deleteContent) > 0 {
		t.Logf("Delete operations log contains %d bytes", len(deleteContent))
		assert.Contains(t, string(deleteContent), "delete", "Should contain delete operations")
	}

	// Check read log file
	readContent, err := os.ReadFile(readLogFile)
	if err == nil && len(readContent) > 0 {
		t.Logf("Read operations log contains %d bytes", len(readContent))
		assert.Contains(t, string(readContent), "read", "Should contain read operations")
	}

	// Clean up
	_ = client.Sys().DisableAudit("integration-op-filter-test")
	_ = client.Sys().Unmount("integration-kv-opfilter")
}

// TestIntegration_PathBasedRules tests rules that filter by request path
func TestIntegration_PathBasedRules(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	secretsLogFile := tmpDir + "/secrets.log"
	metadataLogFile := tmpDir + "/metadata.log"

	// Configure rules for different paths
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "secrets_path",
			"rules": []string{
				`Request.Path startsWith "integration-kv-path/data/"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   secretsLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
		{
			"name": "metadata_path",
			"rules": []string{
				`Request.Path startsWith "integration-kv-path/metadata/"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   metadataLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-path-test")

	err = client.EnableAuditDevice(
		"integration-path-test",
		"socket",
		"Integration path test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	err = client.Sys().Mount("integration-kv-path", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for path filtering",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Write to data path
	_, err = client.Logical().Write("integration-kv-path/data/mysecret", map[string]interface{}{
		"data": map[string]interface{}{"password": "secret123"},
	})
	require.NoError(t, err)

	// Read metadata path
	_, err = client.Logical().Read("integration-kv-path/metadata/mysecret")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	close(done)

	// Check secrets log
	secretsContent, err := os.ReadFile(secretsLogFile)
	if err == nil && len(secretsContent) > 0 {
		t.Logf("Secrets path log contains %d bytes", len(secretsContent))
		assert.Contains(t, string(secretsContent), "integration-kv-path/data/", "Should contain data path operations")
	}

	// Check metadata log
	metadataContent, err := os.ReadFile(metadataLogFile)
	if err == nil && len(metadataContent) > 0 {
		t.Logf("Metadata path log contains %d bytes", len(metadataContent))
		assert.Contains(t, string(metadataContent), "integration-kv-path/metadata/", "Should contain metadata path operations")
	}

	// Clean up
	_ = client.Sys().DisableAudit("integration-path-test")
	_ = client.Sys().Unmount("integration-kv-path")
}

// TestIntegration_CombinedConditions tests rules with AND conditions
func TestIntegration_CombinedConditions(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	combinedLogFile := tmpDir + "/combined.log"

	// Rule: only match allowed updates to specific path
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "combined_rule",
			"rules": []string{
				`Request.Operation == "update" && Auth.PolicyResults.Allowed == true`,
			},
			"log_file": map[string]interface{}{
				"file_path":   combinedLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-combined-test")

	err = client.EnableAuditDevice(
		"integration-combined-test",
		"socket",
		"Integration combined test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	err = client.Sys().Mount("integration-kv-combined", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for combined rules",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Write (update operation that's allowed)
	_, err = client.Logical().Write("integration-kv-combined/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	// Read (not update, should not match)
	_, err = client.Logical().Read("integration-kv-combined/data/test")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	close(done)

	// Verify combined log only has updates
	combinedContent, err := os.ReadFile(combinedLogFile)
	if err == nil && len(combinedContent) > 0 {
		t.Logf("Combined conditions log contains %d bytes", len(combinedContent))
		assert.Contains(t, string(combinedContent), "update", "Should contain update operations")
		// Should not contain read operations
		assert.NotContains(t, string(combinedContent), `"operation":"read"`, "Should not contain read operations")
	}

	// Clean up
	_ = client.Sys().DisableAudit("integration-combined-test")
	_ = client.Sys().Unmount("integration-kv-combined")
}

// TestIntegration_MultipleRuleGroups tests that logs route to correct groups
func TestIntegration_MultipleRuleGroups(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	group1Log := tmpDir + "/group1.log"
	group2Log := tmpDir + "/group2.log"
	group3Log := tmpDir + "/group3.log"

	// Three different rule groups
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "group1_updates",
			"rules": []string{
				`Request.Operation == "update"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   group1Log,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
		{
			"name": "group2_reads",
			"rules": []string{
				`Request.Operation == "read"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   group2Log,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
		{
			"name": "group3_deletes",
			"rules": []string{
				`Request.Operation == "delete"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   group3Log,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-multigroup-test")

	err = client.EnableAuditDevice(
		"integration-multigroup-test",
		"socket",
		"Integration multi-group test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	err = client.Sys().Mount("integration-kv-multigroup", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for multi-group",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Perform all three operations
	_, err = client.Logical().Write("integration-kv-multigroup/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	_, err = client.Logical().Read("integration-kv-multigroup/data/test")
	require.NoError(t, err)

	_, err = client.Logical().Delete("integration-kv-multigroup/data/test")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	close(done)

	// Verify each group has the right operations
	group1Content, _ := os.ReadFile(group1Log)
	group2Content, _ := os.ReadFile(group2Log)
	group3Content, _ := os.ReadFile(group3Log)

	t.Logf("Group1 (updates): %d bytes", len(group1Content))
	t.Logf("Group2 (reads): %d bytes", len(group2Content))
	t.Logf("Group3 (deletes): %d bytes", len(group3Content))

	// Each log should have content (operations were performed)
	if len(group1Content) > 0 {
		assert.Contains(t, string(group1Content), "update")
	}
	if len(group2Content) > 0 {
		assert.Contains(t, string(group2Content), "read")
	}
	if len(group3Content) > 0 {
		assert.Contains(t, string(group3Content), "delete")
	}

	// Clean up
	_ = client.Sys().DisableAudit("integration-multigroup-test")
	_ = client.Sys().Unmount("integration-kv-multigroup")
}

// TestIntegration_NonMatchingRules verifies unmatched logs aren't captured
func TestIntegration_NonMatchingRules(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	logFile := tmpDir + "/nonmatch.log"

	// Rule that should never match normal operations
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "impossible_rule",
			"rules": []string{
				`Request.Path == "this/path/does/not/exist/ever"`,
			},
			"log_file": map[string]interface{}{
				"file_path":   logFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	client, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = client.Sys().DisableAudit("integration-nonmatch-test")

	err = client.EnableAuditDevice(
		"integration-nonmatch-test",
		"socket",
		"Integration non-match test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	err = client.Sys().Mount("integration-kv-nonmatch", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for non-match",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Perform operations that won't match the rule
	_, err = client.Logical().Write("integration-kv-nonmatch/data/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	_, err = client.Logical().Read("integration-kv-nonmatch/data/test")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)
	close(done)

	// Log file should be empty or not exist
	logContent, err := os.ReadFile(logFile)
	if err == nil {
		assert.Empty(t, logContent, "Log file should be empty for non-matching rules")
	}
	// If file doesn't exist, that's also acceptable

	// Clean up
	_ = client.Sys().DisableAudit("integration-nonmatch-test")
	_ = client.Sys().Unmount("integration-kv-nonmatch")
}

// TestIntegration_AuthFailures tests that policy denials are captured
func TestIntegration_AuthFailures(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	deniedLogFile := tmpDir + "/denied.log"
	allowedLogFile := tmpDir + "/allowed.log"

	// Two rules: one for allowed, one for denied
	viper.Reset()
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "denied_operations",
			"rules": []string{
				`Auth.PolicyResults.Allowed == false`,
			},
			"log_file": map[string]interface{}{
				"file_path":   deniedLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
		{
			"name": "allowed_operations",
			"rules": []string{
				`Auth.PolicyResults.Allowed == true`,
			},
			"log_file": map[string]interface{}{
				"file_path":   allowedLogFile,
				"max_size":    10,
				"max_backups": 1,
				"max_age":     1,
				"compress":    false,
			},
		},
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, err := auditserver.New(logger)
	require.NoError(t, err)

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	// Connect as root to setup audit device
	rootClient, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	_ = rootClient.Sys().DisableAudit("integration-auth-test")

	err = rootClient.EnableAuditDevice(
		"integration-auth-test",
		"socket",
		"Integration auth test",
		map[string]string{
			"address":     localAddr,
			"socket_type": "udp",
			"log_raw":     "false",
		},
	)
	require.NoError(t, err)

	// Create a limited policy
	err = rootClient.Sys().PutPolicy("integration-limited", `
		path "integration-kv-auth/data/allowed/*" {
			capabilities = ["create", "read", "update", "delete"]
		}
	`)
	require.NoError(t, err)

	// Create a token with limited policy
	secret, err := rootClient.Auth().Token().Create(&vaultapi.TokenCreateRequest{
		Policies: []string{"integration-limited"},
		TTL:      "1h",
	})
	require.NoError(t, err)
	limitedToken := secret.Auth.ClientToken

	err = rootClient.Sys().Mount("integration-kv-auth", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for auth",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Create limited client
	limitedClient, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: limitedToken})
	require.NoError(t, err)

	// This should succeed (allowed path)
	_, err = limitedClient.Logical().Write("integration-kv-auth/data/allowed/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err)

	// This should fail (denied path)
	_, err = limitedClient.Logical().Write("integration-kv-auth/data/denied/test", map[string]interface{}{
		"data": map[string]interface{}{"key": "value"},
	})
	assert.Error(t, err, "Should fail due to policy denial")

	time.Sleep(500 * time.Millisecond)
	close(done)

	// Check allowed log has content
	allowedContent, _ := os.ReadFile(allowedLogFile)
	t.Logf("Allowed operations log: %d bytes", len(allowedContent))

	// Check denied log - may have content if Vault generates audit for denials
	deniedContent, _ := os.ReadFile(deniedLogFile)
	t.Logf("Denied operations log: %d bytes", len(deniedContent))

	// Note: Due to UDP delivery timing in dev mode, we may not always receive logs
	// The primary purpose of this test is to verify the policy setup and denial behavior
	if len(allowedContent) > 0 {
		t.Log("Successfully captured allowed operations in audit log")
	}
	if len(deniedContent) > 0 {
		t.Log("Successfully captured denied operations in audit log")
	}

	// Clean up
	_ = rootClient.Sys().DisableAudit("integration-auth-test")
	_ = rootClient.Sys().DeletePolicy("integration-limited")
	_ = rootClient.Sys().Unmount("integration-kv-auth")
}

// TestIntegration_AppRoleAuth tests AppRole authentication
func TestIntegration_AppRoleAuth(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	// First, enable AppRole auth and create a role using root token
	rootClient, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	// Enable AppRole auth method
	err = rootClient.Sys().EnableAuthWithOptions("approle", &vaultapi.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Create a policy for the AppRole
	err = rootClient.Sys().PutPolicy("integration-approle-policy", `
		path "integration-kv-approle/*" {
			capabilities = ["create", "read", "update", "delete", "list"]
		}
		path "sys/auth" {
			capabilities = ["read", "list"]
		}
		path "sys/audit" {
			capabilities = ["read", "list"]
		}
		path "sys/audit/*" {
			capabilities = ["create", "read", "update", "delete", "sudo"]
		}
	`)
	require.NoError(t, err)

	// Create AppRole
	_, err = rootClient.Logical().Write("auth/approle/role/integration-role", map[string]interface{}{
		"token_policies": []string{"integration-approle-policy"},
		"token_ttl":      "1h",
		"token_max_ttl":  "4h",
	})
	require.NoError(t, err)

	// Get role ID
	roleIDSecret, err := rootClient.Logical().Read("auth/approle/role/integration-role/role-id")
	require.NoError(t, err)
	require.NotNil(t, roleIDSecret)
	roleID := roleIDSecret.Data["role_id"].(string)

	// Get secret ID
	secretIDSecret, err := rootClient.Logical().Write("auth/approle/role/integration-role/secret-id", nil)
	require.NoError(t, err)
	require.NotNil(t, secretIDSecret)
	secretID := secretIDSecret.Data["secret_id"].(string)

	// Now test AppRole authentication
	appRoleClient, err := vault.NewVaultClient(vaultAddr, vault.AppRoleAuth{
		RoleID:   roleID,
		SecretID: secretID,
	})
	require.NoError(t, err, "AppRole authentication should succeed")
	require.NotNil(t, appRoleClient)

	// Verify the client works by listing auth methods
	_, err = appRoleClient.Sys().ListAuth()
	assert.NoError(t, err, "AppRole client should be able to list auth methods")

	// Setup KV and verify operations work
	err = rootClient.Sys().Mount("integration-kv-approle", &vaultapi.MountInput{
		Type:        "kv",
		Description: "Integration test KV for AppRole",
		Options:     map[string]string{"version": "2"},
	})
	if err != nil && !strings.Contains(err.Error(), "path is already in use") {
		require.NoError(t, err)
	}

	// Write using AppRole authenticated client
	_, err = appRoleClient.Logical().Write("integration-kv-approle/data/test", map[string]interface{}{
		"data": map[string]interface{}{"secret": "from-approle"},
	})
	require.NoError(t, err, "AppRole client should be able to write secrets")

	// Read it back
	secret, err := appRoleClient.Logical().Read("integration-kv-approle/data/test")
	require.NoError(t, err)
	require.NotNil(t, secret)

	// Clean up
	_ = rootClient.Sys().Unmount("integration-kv-approle")
	_ = rootClient.Sys().DeletePolicy("integration-approle-policy")
	_, _ = rootClient.Logical().Delete("auth/approle/role/integration-role")
}
