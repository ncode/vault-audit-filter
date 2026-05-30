/*
Copyright © 2024 Juliano Martinez <juliano@martinez.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ncode/vault-audit-filter/pkg/auditserver"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditServerCmd_InvalidRuleGroups(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_address", "127.0.0.1:1269")
	viper.Set("rule_groups", "invalid_value")

	err := auditServerCmd.RunE(auditServerCmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create audit server")
}

func TestAuditServerCmd_ValidConfig(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_address", "127.0.0.1:1269")
	viper.Set("rule_groups", []map[string]interface{}{
		{
			"name": "test_group",
			"rules": []string{
				"Request.Operation == 'read'",
			},
			"log_file": map[string]interface{}{
				"file_path": "/tmp/test-audit.log",
				"max_size":  10,
			},
		},
	})

	// We can't actually test gnet.Serve without starting a server,
	// but we can at least verify the command is properly configured
	assert.NotNil(t, auditServerCmd)
	assert.Equal(t, "auditServer", auditServerCmd.Use)
	assert.NotNil(t, auditServerCmd.RunE)
}

func TestAuditServerRuntimeSettingsFromViper(t *testing.T) {
	viper.Reset()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	viper.Set("vault.audit_protocol", "tcp")
	viper.Set("async.queue_size", 9)
	viper.Set("async.workers", 3)
	viper.Set("async.enqueue_mode", "wait")
	viper.Set("async.enqueue_timeout", "13ms")
	viper.Set("async.timeout", "19ms")
	viper.Set("async.durable.enabled", true)
	viper.Set("async.durable.dir", t.TempDir())
	viper.Set("async.retry.max_attempts", 6)
	viper.Set("async.retry.backoff", "29ms")
	viper.Set("rule_groups", []map[string]interface{}{{
		"name":     "configured",
		"rules":    []string{"Request.Operation == 'read'"},
		"log_file": map[string]interface{}{"file_path": logPath, "max_size": 1},
	}})

	settings, err := auditServerRuntimeSettings()
	require.NoError(t, err)
	assert.Equal(t, "tcp", settings.AuditProtocol)
	assert.Equal(t, 9, settings.Async.QueueSize)
	assert.Equal(t, 3, settings.Async.Workers)
	assert.Equal(t, "wait", settings.Async.EnqueueMode)
	assert.Equal(t, 13*time.Millisecond, settings.Async.EnqueueTimeout)
	assert.Equal(t, 19*time.Millisecond, settings.Async.Timeout)
	assert.True(t, settings.Async.Durable.Enabled)
	assert.Equal(t, 6, settings.Async.Retry.MaxAttempts)
	assert.Equal(t, 29*time.Millisecond, settings.Async.Retry.Backoff)
	require.Len(t, settings.RuleGroups, 1)
	assert.Equal(t, "configured", settings.RuleGroups[0].Name)
	assert.Equal(t, logPath, settings.RuleGroups[0].LogFile.FilePath)
}

func TestAuditServerRuntimeSettings_InvalidAsyncValuesFallBackToDefaults(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_protocol", "udp")
	viper.Set("async.queue_size", 0)
	viper.Set("async.workers", -1)
	viper.Set("async.enqueue_mode", "invalid")
	viper.Set("async.enqueue_timeout", "bad")
	viper.Set("async.timeout", "also-bad")
	viper.Set("async.durable.dir", "")
	viper.Set("async.retry.max_attempts", 0)
	viper.Set("async.retry.backoff", "worse")
	viper.Set("rule_groups", []map[string]interface{}{})

	settings, err := auditServerRuntimeSettings()
	require.NoError(t, err)
	defaults := auditserver.DefaultRuntimeSettings()
	assert.Equal(t, defaults.Async.QueueSize, settings.Async.QueueSize)
	assert.Equal(t, defaults.Async.Workers, settings.Async.Workers)
	assert.Equal(t, defaults.Async.EnqueueMode, settings.Async.EnqueueMode)
	assert.Equal(t, defaults.Async.EnqueueTimeout, settings.Async.EnqueueTimeout)
	assert.Equal(t, defaults.Async.Timeout, settings.Async.Timeout)
	assert.Equal(t, defaults.Async.Durable.Dir, settings.Async.Durable.Dir)
	assert.Equal(t, defaults.Async.Retry.MaxAttempts, settings.Async.Retry.MaxAttempts)
	assert.Equal(t, defaults.Async.Retry.Backoff, settings.Async.Retry.Backoff)
}

func TestAuditServerRuntimeSettings_InvalidProtocol(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_protocol", "invalid")

	_, err := auditServerRuntimeSettings()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported vault.audit_protocol")
}

func TestAuditServerCmd_RunE_InvokesGnetRun(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_address", "bad host")
	viper.Set("rule_groups", []map[string]interface{}{})

	err := auditServerCmd.RunE(auditServerCmd, []string{})
	assert.Error(t, err)
}

func TestAuditServerCmd_RunE_ListenAddressError(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_protocol", "invalid")
	viper.Set("vault.audit_address", "127.0.0.1:1269")
	viper.Set("rule_groups", []map[string]interface{}{})

	err := auditServerCmd.RunE(auditServerCmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported vault.audit_protocol")
}

func TestAuditServerCmd_ListenAddress(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_address", "127.0.0.1:1269")

	addr, err := auditServerListenAddress()
	require.NoError(t, err)
	assert.Equal(t, "udp://127.0.0.1:1269", addr)

	viper.Set("vault.audit_protocol", "tcp")
	addr, err = auditServerListenAddress()
	require.NoError(t, err)
	assert.Equal(t, "tcp://127.0.0.1:1269", addr)

	viper.Set("vault.audit_protocol", "invalid")
	_, err = auditServerListenAddress()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported vault.audit_protocol")
}
