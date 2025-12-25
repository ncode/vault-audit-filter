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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestRootCmd_Exists(t *testing.T) {
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "vault-audit-filter", rootCmd.Use)
}

func TestRootCmd_HasSubcommands(t *testing.T) {
	commands := rootCmd.Commands()
	assert.GreaterOrEqual(t, len(commands), 2)

	var hasSetup, hasAuditServer bool
	for _, cmd := range commands {
		if cmd.Use == "setup" {
			hasSetup = true
		}
		if cmd.Use == "auditServer" {
			hasAuditServer = true
		}
	}
	assert.True(t, hasSetup, "setup command should be registered")
	assert.True(t, hasAuditServer, "auditServer command should be registered")
}

func TestRootCmd_PersistentFlags(t *testing.T) {
	flags := rootCmd.PersistentFlags()

	configFlag := flags.Lookup("config")
	assert.NotNil(t, configFlag)

	vaultAddressFlag := flags.Lookup("vault.address")
	assert.NotNil(t, vaultAddressFlag)
	assert.Equal(t, "http://127.0.0.1:8200", vaultAddressFlag.DefValue)

	vaultTokenFlag := flags.Lookup("vault.token")
	assert.NotNil(t, vaultTokenFlag)

	vaultAuditPathFlag := flags.Lookup("vault.audit_path")
	assert.NotNil(t, vaultAuditPathFlag)

	vaultAuditAddressFlag := flags.Lookup("vault.audit_address")
	assert.NotNil(t, vaultAuditAddressFlag)
	assert.Equal(t, "127.0.0.1:1269", vaultAuditAddressFlag.DefValue)
}

func TestInitConfig_WithConfigFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
vault:
  address: "http://test-vault:8200"
  token: "test-token"
rule_groups:
  - name: test
    rules:
      - "Request.Operation == 'read'"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	// Reset viper and set config file
	viper.Reset()
	cfgFile = configPath
	initConfig()

	assert.Equal(t, "http://test-vault:8200", viper.GetString("vault.address"))
	assert.Equal(t, "test-token", viper.GetString("vault.token"))

	ruleGroups := viper.Get("rule_groups")
	assert.NotNil(t, ruleGroups)

	// Reset for other tests
	cfgFile = ""
	viper.Reset()
}

func TestInitConfig_NoRuleGroups(t *testing.T) {
	viper.Reset()
	cfgFile = ""

	// initConfig should log that no rules are defined
	// We just verify it doesn't panic
	initConfig()

	// Reset for other tests
	viper.Reset()
}

func TestExecute_Help(t *testing.T) {
	// Test that Execute doesn't panic with help flag
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vault-audit-filter", "--help"}

	// Capture output
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})

	// This should not panic
	// We don't call Execute() directly as it calls os.Exit
	err := rootCmd.Help()
	assert.NoError(t, err)
}
