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

	"github.com/ncode/vault-audit-filter/pkg/auditserver"
	"github.com/panjf2000/gnet/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// auditServerCmd represents the auditServer command
var auditServerCmd = &cobra.Command{
	Use:   "auditServer",
	Short: "Start the audit server to receive and filter Vault audit logs",
	Long:  `Starts an audit server that receives Vault audit logs and filters them based on configured rules.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, err := auditServerListenAddress()
		if err != nil {
			return err
		}
		settings, err := auditServerRuntimeSettings()
		if err != nil {
			return fmt.Errorf("failed to create audit server: %w", err)
		}
		server, err := auditserver.New(logger, settings)
		if err != nil {
			return fmt.Errorf("failed to create audit server: %w", err)
		}
		return gnet.Run(server, addr, gnet.WithMulticore(true))
	},
}

func auditServerListenAddress() (string, error) {
	protocol, err := vaultAuditProtocol()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s://%s", protocol, viper.GetString("vault.audit_address")), nil
}

func init() {
	rootCmd.AddCommand(auditServerCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// auditServerCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// auditServerCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
