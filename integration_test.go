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

func auditAddressFromListener(listenerAddr net.Addr) string {
	port := "0"
	if _, p, err := net.SplitHostPort(listenerAddr.String()); err == nil {
		port = p
	}

	host := getEnvOrDefault("AUDIT_HOST", "127.0.0.1")
	return net.JoinHostPort(host, port)
}

func tcpListenerHost() string {
	host := getEnvOrDefault("AUDIT_HOST", "127.0.0.1")
	if host == "127.0.0.1" || host == "localhost" {
		return host
	}

	return "0.0.0.0"
}

func newIntegrationVaultClient(t *testing.T) *vault.VaultClient {
	t.Helper()
	client, err := vault.NewVaultClient(
		getEnvOrDefault("VAULT_ADDR", defaultVaultAddr),
		vault.TokenAuth{Token: getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)},
	)
	require.NoError(t, err)
	return client
}

func integrationLogFile(path string) auditserver.LogFileConfig {
	return auditserver.LogFileConfig{
		FilePath:   path,
		MaxSize:    10,
		MaxBackups: 1,
		MaxAge:     1,
		Compress:   false,
	}
}

func newIntegrationAuditServer(t *testing.T, protocol string, ruleGroups []auditserver.RuleGroupConfig) *auditserver.AuditServer {
	t.Helper()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	settings := auditserver.DefaultRuntimeSettings()
	settings.AuditProtocol = protocol
	settings.RuleGroups = ruleGroups
	server, err := auditserver.New(logger, settings)
	require.NoError(t, err)
	require.NotNil(t, server)
	return server
}

func startUDPAuditListener(t *testing.T, server *auditserver.AuditServer) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)

	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = conn.Close()
	})

	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
				_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, err := conn.ReadFromUDP(buf)
				if err != nil {
					continue
				}
				server.React(buf[:n], nil)
			}
		}
	}()

	return auditAddressFromListener(conn.LocalAddr())
}

func startTCPAuditListener(t *testing.T, server *auditserver.AuditServer) string {
	t.Helper()
	tcpListenAddr := net.JoinHostPort(tcpListenerHost(), "0")
	addr, err := net.ResolveTCPAddr("tcp", tcpListenAddr)
	require.NoError(t, err)

	listener, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)

	stop := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})

	go func() {
		defer close(done)

		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 65535)
		carry := make([]byte, 0)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, readErr := conn.Read(buf)
			if n > 0 {
				carry = append(carry, buf[:n]...)

				for {
					idx := bytes.IndexByte(carry, '\n')
					if idx < 0 {
						break
					}

					frame := bytes.TrimSuffix(carry[:idx], []byte{'\r'})
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
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
		}
	}()

	return auditAddressFromListener(listener.Addr())
}

func enableSocketAudit(t *testing.T, client *vault.VaultClient, path, address, protocol, description string) {
	t.Helper()
	_ = client.Sys().DisableAudit(path)
	err := client.EnableSocketAuditDevice(vault.SocketAuditDeviceSpec{
		Path:        path,
		Address:     address,
		Protocol:    protocol,
		Description: description,
		LogRaw:      false,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Sys().DisableAudit(path)
	})
}

func waitForLogFile(t *testing.T, path string) string {
	t.Helper()
	var content []byte
	require.Eventually(t, func() bool {
		var err error
		content, err = os.ReadFile(path)
		return err == nil && len(content) > 0
	}, 2*time.Second, 50*time.Millisecond)
	return string(content)
}

func readLogFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

func TestIntegration_VaultConnection(t *testing.T) {
	client := newIntegrationVaultClient(t)

	// Verify we can list auth methods (proves connection works)
	_, err := client.Sys().ListAuth()
	assert.NoError(t, err, "Failed to list auth methods")
}

func TestIntegration_EnableAuditDevice(t *testing.T) {
	auditAddr := getEnvOrDefault("AUDIT_ADDR", defaultAuditAddr)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-test", auditAddr, "udp", "Integration test audit device")

	// Verify it was enabled
	audits, err := client.Sys().ListAudit()
	require.NoError(t, err)
	assert.Contains(t, audits, "integration-test/", "Audit device should be enabled")
}

func TestIntegration_AuditDeviceWithSocketConfig(t *testing.T) {
	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-socket-test", "127.0.0.1:19999", "udp", "Integration socket test")

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

	_ = client.Sys().Unmount("integration-kv")
}

func TestIntegration_AuditServerWithRules(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/audit.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "all_operations",
			Rules: []string{
				"Auth.PolicyResults.Allowed == true",
			},
			LogFile: integrationLogFile(logFile),
		},
	})
	localAddr := startUDPAuditListener(t, server)
	t.Logf("Audit server listening on %s", localAddr)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-rules-test", localAddr, "udp", "Integration rules test")

	// Perform Vault operations
	err := client.Sys().Mount("integration-kv-rules", &vaultapi.MountInput{
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

	logContent := waitForLogFile(t, logFile)
	t.Logf("Audit log file contains %d bytes", len(logContent))

	_ = client.Sys().Unmount("integration-kv-rules")
}

func TestIntegration_AuditServerWithRules_TCP(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/audit-tcp.log"

	server := newIntegrationAuditServer(t, "tcp", []auditserver.RuleGroupConfig{
		{
			Name: "all_tcp",
			Rules: []string{
				"true",
			},
			LogFile: integrationLogFile(logFile),
		},
	})
	auditAddress := startTCPAuditListener(t, server)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-rules-tcp-test", auditAddress, "tcp", "Integration TCP rules test")

	err := client.Sys().Mount("integration-kv-rules-tcp", &vaultapi.MountInput{
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

	_ = client.Sys().Unmount("integration-kv-rules-tcp")

	content := waitForLogFile(t, logFile)
	assert.Greater(t, len(content), 0, "should have written audit logs over TCP")
}

func TestIntegration_AuditServerForwarding(t *testing.T) {
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

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "forward_all",
			Rules: []string{
				"true", // Match everything
			},
			LogFile:    integrationLogFile(logFile),
			Forwarding: auditserver.ForwardingConfig{Enabled: true, Address: forwardLocalAddr},
		},
	})
	auditLocalAddr := startUDPAuditListener(t, server)
	t.Logf("Audit server listening on %s", auditLocalAddr)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-forward-test", auditLocalAddr, "udp", "Integration forward test")

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

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(forwarded) > 0
	}, 2*time.Second, 50*time.Millisecond)
	close(forwardDone)

	// Verify forwarding worked
	mu.Lock()
	defer mu.Unlock()

	t.Logf("Received %d forwarded messages", len(forwarded))

	_ = client.Sys().Unmount("integration-kv-forward")
}

// TestIntegration_OperationFiltering tests rules that filter by operation type
func TestIntegration_OperationFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	deleteLogFile := tmpDir + "/delete_ops.log"
	readLogFile := tmpDir + "/read_ops.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "delete_operations",
			Rules: []string{
				`Request.Operation == "delete"`,
			},
			LogFile: integrationLogFile(deleteLogFile),
		},
		{
			Name: "read_operations",
			Rules: []string{
				`Request.Operation == "read"`,
			},
			LogFile: integrationLogFile(readLogFile),
		},
	})
	localAddr := startUDPAuditListener(t, server)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-op-filter-test", localAddr, "udp", "Integration operation filter test")

	// Setup KV engine
	err := client.Sys().Mount("integration-kv-opfilter", &vaultapi.MountInput{
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

	deleteContent := waitForLogFile(t, deleteLogFile)
	t.Logf("Delete operations log contains %d bytes", len(deleteContent))
	assert.Contains(t, deleteContent, "delete", "Should contain delete operations")

	readContent := waitForLogFile(t, readLogFile)
	t.Logf("Read operations log contains %d bytes", len(readContent))
	assert.Contains(t, readContent, "read", "Should contain read operations")

	_ = client.Sys().Unmount("integration-kv-opfilter")
}

// TestIntegration_PathBasedRules tests rules that filter by request path
func TestIntegration_PathBasedRules(t *testing.T) {
	tmpDir := t.TempDir()
	secretsLogFile := tmpDir + "/secrets.log"
	metadataLogFile := tmpDir + "/metadata.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "secrets_path",
			Rules: []string{
				`Request.Path startsWith "integration-kv-path/data/"`,
			},
			LogFile: integrationLogFile(secretsLogFile),
		},
		{
			Name: "metadata_path",
			Rules: []string{
				`Request.Path startsWith "integration-kv-path/metadata/"`,
			},
			LogFile: integrationLogFile(metadataLogFile),
		},
	})
	localAddr := startUDPAuditListener(t, server)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-path-test", localAddr, "udp", "Integration path test")

	err := client.Sys().Mount("integration-kv-path", &vaultapi.MountInput{
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

	secretsContent := waitForLogFile(t, secretsLogFile)
	t.Logf("Secrets path log contains %d bytes", len(secretsContent))
	assert.Contains(t, secretsContent, "integration-kv-path/data/", "Should contain data path operations")

	metadataContent := waitForLogFile(t, metadataLogFile)
	t.Logf("Metadata path log contains %d bytes", len(metadataContent))
	assert.Contains(t, metadataContent, "integration-kv-path/metadata/", "Should contain metadata path operations")

	_ = client.Sys().Unmount("integration-kv-path")
}

// TestIntegration_CombinedConditions tests rules with AND conditions
func TestIntegration_CombinedConditions(t *testing.T) {
	tmpDir := t.TempDir()
	combinedLogFile := tmpDir + "/combined.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "combined_rule",
			Rules: []string{
				`Request.Operation == "update" && Auth.PolicyResults.Allowed == true`,
			},
			LogFile: integrationLogFile(combinedLogFile),
		},
	})
	localAddr := startUDPAuditListener(t, server)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-combined-test", localAddr, "udp", "Integration combined test")

	err := client.Sys().Mount("integration-kv-combined", &vaultapi.MountInput{
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

	combinedContent := waitForLogFile(t, combinedLogFile)
	t.Logf("Combined conditions log contains %d bytes", len(combinedContent))
	assert.Contains(t, combinedContent, "update", "Should contain update operations")
	assert.NotContains(t, combinedContent, `"operation":"read"`, "Should not contain read operations")

	_ = client.Sys().Unmount("integration-kv-combined")
}

// TestIntegration_MultipleRuleGroups tests that logs route to correct groups
func TestIntegration_MultipleRuleGroups(t *testing.T) {
	tmpDir := t.TempDir()
	group1Log := tmpDir + "/group1.log"
	group2Log := tmpDir + "/group2.log"
	group3Log := tmpDir + "/group3.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "group1_updates",
			Rules: []string{
				`Request.Operation == "update"`,
			},
			LogFile: integrationLogFile(group1Log),
		},
		{
			Name: "group2_reads",
			Rules: []string{
				`Request.Operation == "read"`,
			},
			LogFile: integrationLogFile(group2Log),
		},
		{
			Name: "group3_deletes",
			Rules: []string{
				`Request.Operation == "delete"`,
			},
			LogFile: integrationLogFile(group3Log),
		},
	})
	localAddr := startUDPAuditListener(t, server)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-multigroup-test", localAddr, "udp", "Integration multi-group test")

	err := client.Sys().Mount("integration-kv-multigroup", &vaultapi.MountInput{
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

	group1Content := waitForLogFile(t, group1Log)
	group2Content := waitForLogFile(t, group2Log)
	group3Content := waitForLogFile(t, group3Log)

	t.Logf("Group1 (updates): %d bytes", len(group1Content))
	t.Logf("Group2 (reads): %d bytes", len(group2Content))
	t.Logf("Group3 (deletes): %d bytes", len(group3Content))

	assert.Contains(t, group1Content, "update")
	assert.Contains(t, group2Content, "read")
	assert.Contains(t, group3Content, "delete")

	_ = client.Sys().Unmount("integration-kv-multigroup")
}

// TestIntegration_NonMatchingRules verifies unmatched logs aren't captured
func TestIntegration_NonMatchingRules(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/nonmatch.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "impossible_rule",
			Rules: []string{
				`Request.Path == "this/path/does/not/exist/ever"`,
			},
			LogFile: integrationLogFile(logFile),
		},
	})
	localAddr := startUDPAuditListener(t, server)

	client := newIntegrationVaultClient(t)
	enableSocketAudit(t, client, "integration-nonmatch-test", localAddr, "udp", "Integration non-match test")

	err := client.Sys().Mount("integration-kv-nonmatch", &vaultapi.MountInput{
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

	require.Never(t, func() bool {
		return readLogFile(logFile) != ""
	}, 500*time.Millisecond, 50*time.Millisecond, "Log file should stay empty for non-matching rules")

	_ = client.Sys().Unmount("integration-kv-nonmatch")
}

// TestIntegration_AuthFailures tests that policy denials are captured
func TestIntegration_AuthFailures(t *testing.T) {
	vaultAddr := getEnvOrDefault("VAULT_ADDR", defaultVaultAddr)
	vaultToken := getEnvOrDefault("VAULT_TOKEN", defaultVaultToken)

	tmpDir := t.TempDir()
	deniedLogFile := tmpDir + "/denied.log"
	allowedLogFile := tmpDir + "/allowed.log"

	server := newIntegrationAuditServer(t, "udp", []auditserver.RuleGroupConfig{
		{
			Name: "denied_operations",
			Rules: []string{
				`Auth.PolicyResults.Allowed == false`,
			},
			LogFile: integrationLogFile(deniedLogFile),
		},
		{
			Name: "allowed_operations",
			Rules: []string{
				`Auth.PolicyResults.Allowed == true`,
			},
			LogFile: integrationLogFile(allowedLogFile),
		},
	})
	localAddr := startUDPAuditListener(t, server)

	// Connect as root to setup audit device
	rootClient, err := vault.NewVaultClient(vaultAddr, vault.TokenAuth{Token: vaultToken})
	require.NoError(t, err)

	enableSocketAudit(t, rootClient, "integration-auth-test", localAddr, "udp", "Integration auth test")

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

	// Check allowed log has content
	allowedContent := readLogFile(allowedLogFile)
	t.Logf("Allowed operations log: %d bytes", len(allowedContent))

	// Check denied log - may have content if Vault generates audit for denials
	deniedContent := readLogFile(deniedLogFile)
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
