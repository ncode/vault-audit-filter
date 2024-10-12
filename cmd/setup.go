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
	"os"

	"github.com/ncode/vault-audit-filter/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup vault audit device",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if viper.GetString("vault.token") == "" {
			logger.Error("vault.token is required")
			os.Exit(1)
		}

		client, err := vault.NewVaultClient(viper.GetString("vault.address"), vault.TokenAuth{Token: viper.GetString("vault.token")})
		if err != nil {
			logger.Error("setup", "unable to setup vault client", err.Error())
			os.Exit(1)
		}
		err = client.EnableAuditDevice(
			viper.GetString("vault.audit_path"),
			"socket",
			viper.GetString("vault.audit_description"),
			map[string]string{
				"address":     viper.GetString("vault.audit_address"),
				"description": viper.GetString("vault.audit_description"),
				"socket_type": "udp",
				"log_raw":     "false",
			},
		)
		if err != nil {
			logger.Error("setup", "unable to enable audit device", err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// setupCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// setupCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
