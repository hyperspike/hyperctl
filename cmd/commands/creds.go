package commands

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(credsCmd)
}
var clusterId string
var credsCmd = creds()

func creds() *cobra.Command {
	var command = &cobra.Command {
		Use: "creds",
		Short: "fetch the creds for a hyperspike cluster",
		Run: func(c *cobra.Command, args []string) {
		},
	}

	command.Flags().StringVarP(&clusterId,  "cluster",  "c", "", "Cluster ID to fetch")
	return command
}
