/*
Copyright © 2024 Juliano Martinez
*/
package cmd

import (
	"os"

	"github.com/ncode/courier/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup vault audit device",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := vault.NewVaultClient(viper.GetString("vault.source.address"), vault.TokenAuth{Token: viper.GetString("vault.source.token")})
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
