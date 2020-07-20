package commands

import (
	"github.com/spf13/cobra"
	"hyperspike.io/eng/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(BootCommand())
}

var provider string
var master bool

func BootCommand() *cobra.Command {
	var bootCmd =  &cobra.Command {
		Use: "boot",
		Short: "boot a node into the cluster",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init()
			p.CreateCluster()

		},
	}

	bootCmd.Flags().StringVarP(&provider, "provider", "p", "aws", "the cloud provider")
	bootCmd.Flags().BoolVarP(&master, "master", "m", false, "master boot mode")
	return bootCmd
}
