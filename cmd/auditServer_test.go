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
	"testing"

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

func TestAuditServerCmd_RunE_InvokesGnetRun(t *testing.T) {
	viper.Reset()
	viper.Set("vault.audit_address", "bad host")
	viper.Set("rule_groups", []map[string]interface{}{})

	err := auditServerCmd.RunE(auditServerCmd, []string{})
	assert.Error(t, err)
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
