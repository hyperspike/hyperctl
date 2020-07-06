package commands

import (
	"github.com/spf13/cobra"
	"hyperspike.io/eng/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(createCmd)
}

var createCmd =  &cobra.Command {
	Use: "create",
	Short: "Create A Hyperspike Kubernetes Cluster",
	Run: func(c *cobra.Command, args []string) {
		p := aws.Init()
		p.CreateCluster()
	},
}
