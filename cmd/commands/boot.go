package commands

import (
	"github.com/spf13/cobra"
	"hyperspike.io/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(bootCmd)
}
var region, cidr, service, vpcId, master, node string
var bootCmd = bootCommand()

func bootCommand() *cobra.Command {
	var command = &cobra.Command {
		Use: "boot",
		Short: "Create A Hyperspike Kubernetes Cluster",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init(region, cidr, service)
			p.CreateCluster(vpcId, master, node)
		},
	}

	command.Flags().StringVarP(&region,  "region",  "r", "",     "The region to deploy to")
	command.Flags().StringVarP(&cidr,    "cidr",    "c", "10.20.0.0/16",  "The network space to create")
	command.Flags().StringVarP(&service, "service", "s", "172.16.0.0/18", "The service CIDR to create")
	command.Flags().StringVarP(&vpcId,   "vpc-id",  "V", "",              "Deploy to an existing VPC, ignores cidr, use vpcId")
	command.Flags().StringVarP(&master,  "control-plane-type", "C", "t3a.medium", "the control-plane instance type")
	command.Flags().StringVarP(&node,    "node-type", "n", "t3a.medium", "the node instance type")
	return command
}
