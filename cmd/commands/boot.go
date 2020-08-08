package commands

import (
	"fmt"
	"os"
	"os/exec"
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
			// p.CreateCluster()
			endpoint, err := p.GetAPIEndpoint()
			if err != nil {
				fmt.Println("error fetching endpoint", err)
				os.Exit(1)
			}
			token, err := p.GetAPIToken()
			if err != nil {
				fmt.Println("error getting token", err)
				os.Exit(1)
			}
			caHash, err := p.GetAPICAHash()
			if err != nil {
				fmt.Println("error getting CA Hash", err)
				os.Exit(1)
			}
			fmt.Printf("Join %s %s\n", endpoint, token)
			cmd := exec.Command("sudo", "su", "-c", "kubeadm join --cri-socket /run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight")
			err = cmd.Run()
			if err != nil {
				fmt.Printf("kubeadm command failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("boot successful")
			os.Exit(0)
		},
	}

	bootCmd.Flags().StringVarP(&provider, "provider", "p", "aws", "the cloud provider")
	return bootCmd
}
