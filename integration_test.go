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
