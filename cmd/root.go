/*
Copyright © 2024 Juliano Martinez

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
	Use:   "courier",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.courier.yaml)")
	rootCmd.PersistentFlags().String("vault.source.address", "http://127.0.0.1:8200", "Vault source address")
	rootCmd.PersistentFlags().String("vault.source.token", "", "Vault source token")
	rootCmd.PersistentFlags().String("vault.audit_path", "/courier", "Vault audit path")
	rootCmd.PersistentFlags().String("vault.audit_address", "127.0.0.1:1269", "Courier audit device address to receive the audit")
	rootCmd.PersistentFlags().String("vault.audit_description", "Courier audit device", "Vault audit description")

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

		// Search config in home directory with name ".courier" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".courier")
	}

	viper.BindPFlag("vault.source.address", rootCmd.PersistentFlags().Lookup("vault.source.address"))
	viper.BindPFlag("vault.source.token", rootCmd.PersistentFlags().Lookup("vault.source.token"))
	viper.BindPFlag("vault.audit_path", rootCmd.PersistentFlags().Lookup("vault.audit_path"))
	viper.BindPFlag("vault.audit_address", rootCmd.PersistentFlags().Lookup("vault.audit_address"))
	viper.BindPFlag("vault.audit_description", rootCmd.PersistentFlags().Lookup("vault.audit_description"))

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	if viper.GetString("vault.source.token") == "" {
		logger.Error("vault.source.token is required")
		os.Exit(1)
	}
}
