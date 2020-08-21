package commands

import (
	"github.com/spf13/cobra"
	"hyperspike.io/eng/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(createCmd)
}
var region, cidr string
var createCmd = createCommand()

func createCommand() *cobra.Command {
	var command = &cobra.Command {
		Use: "create",
		Short: "Create A Hyperspike Kubernetes Cluster",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init(region, cidr)
			p.CreateCluster()
		},
	}

	command.Flags().StringVarP(&region, "region", "r", "us-east-2", "The region to deploy to")
	command.Flags().StringVarP(&cidr,   "cidr",   "c", "10.20.0.0/16", "The network space to create")
	return command
}
