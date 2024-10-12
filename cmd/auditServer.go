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
	"log"

	"github.com/ncode/vault-audit-filter/pkg/auditserver"
	"github.com/panjf2000/gnet"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

// auditServerCmd represents the auditServer command
var auditServerCmd = &cobra.Command{
	Use:   "auditServer",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		addr := fmt.Sprintf("udp://%s", viper.GetString("vault.audit_address"))
		server, err := auditserver.New(nil)
		if err != nil {
			logger.Error(err.Error())
		}
		log.Fatal(gnet.Serve(server, addr, gnet.WithMulticore(true)))
	},
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
