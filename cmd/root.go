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
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *slog.Logger

func init() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault-audit-filter",
	Short: "Filter and log HashiCorp Vault audit logs based on configurable rules",
	Long: `vault-audit-filter is a tool designed to filter and log HashiCorp Vault
audit logs based on configurable rules. It provides fine-grained control over
how Vault audit events are processed and categorized, allowing you to capture
critical events while reducing noise from routine operations.

Use 'setup' to configure Vault to send audit logs to this service.
Use 'auditServer' to start the UDP server that receives and filters logs.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-audit-filter.yaml)")
	rootCmd.PersistentFlags().String("vault.address", "http://127.0.0.1:8200", "Vault source address")
	rootCmd.PersistentFlags().String("vault.token", "", "Vault source token")
	rootCmd.PersistentFlags().String("vault.audit_path", "/vault-audit-filter", "Vault audit path")
	rootCmd.PersistentFlags().String("vault.audit_address", "127.0.0.1:1269", "Courier audit device address to receive the audit")
	rootCmd.PersistentFlags().String("vault.audit_description", "Courier audit device", "Vault audit description")
	rootCmd.PersistentFlags().String("vault.audit_protocol", "udp", "Vault socket transport for audit delivery: udp or tcp")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".vault-audit-filter" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault-audit-filter")
	}

	viper.BindPFlag("vault.address", rootCmd.PersistentFlags().Lookup("vault.address"))
	viper.BindPFlag("vault.token", rootCmd.PersistentFlags().Lookup("vault.token"))
	viper.BindPFlag("vault.audit_path", rootCmd.PersistentFlags().Lookup("vault.audit_path"))
	viper.BindPFlag("vault.audit_address", rootCmd.PersistentFlags().Lookup("vault.audit_address"))
	viper.BindPFlag("vault.audit_description", rootCmd.PersistentFlags().Lookup("vault.audit_description"))
	viper.BindPFlag("vault.audit_protocol", rootCmd.PersistentFlags().Lookup("vault.audit_protocol"))

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	ruleGroups := viper.Get("rule_groups")
	if ruleGroups == nil {
		logger.Info("No rules defined in configuration; all audit logs will be printed")
	} else if slice, ok := ruleGroups.([]interface{}); ok && len(slice) == 0 {
		logger.Info("No rules defined in configuration; all audit logs will be printed")
	}
}

func vaultAuditProtocol() (string, error) {
	protocol := strings.ToLower(strings.TrimSpace(viper.GetString("vault.audit_protocol")))
	if protocol == "" {
		protocol = "udp"
	}

	switch protocol {
	case "udp", "tcp":
		return protocol, nil
	default:
		return "", fmt.Errorf("unsupported vault.audit_protocol %q (allowed: udp, tcp)", protocol)
	}
}
