package commands

import (
	"os"
	"os/exec"
	log "github.com/sirupsen/logrus"
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
			p := aws.Init("", "")
			// p.CreateCluster()
			endpoint, err := p.GetAPIEndpoint()
			if err != nil {
				log.Error("error fetching endpoint", err)
				os.Exit(1)
			}
			token, err := p.GetAPIToken()
			if err != nil {
				log.Error("error getting token", err)
				os.Exit(1)
			}
			caHash, err := p.GetAPICAHash()
			if err != nil {
				log.Error("error getting CA Hash", err)
				os.Exit(1)
			}
			if p.IsMaster() {
				// prep static pods
				// get lock ?
				// is init ?
				// init
				var uninitialized bool
				if (uninitialized) {
					cmd := exec.Command("sudo", "su", "-c", "kubeadm init --cri-socket /run/crio/crio.sock --config kubeadm.conf")
					err = cmd.Run()
					if err != nil {
						log.Error("kubeadm command failed: %v\n", err)
						os.Exit(1)
					}
				} else {
					cmd := exec.Command("sudo", "su", "-c", "kubeadm join --cri-socket /run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight")
					err = cmd.Run()
					if err != nil {
						log.Error("kubeadm command failed: %v\n", err)
						os.Exit(1)
					}
				}
			} else {
				log.Info("Join %s %s\n", endpoint, token)
				cmd := exec.Command("sudo", "su", "-c", "kubeadm join --cri-socket /run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight")
				err = cmd.Run()
				if err != nil {
					log.Error("kubeadm command failed: %v\n", err)
					os.Exit(1)
				}
				log.Error("boot successful")
				os.Exit(0)
			}
		},
	}

	bootCmd.Flags().StringVarP(&provider, "provider", "p", "aws", "the cloud provider")
	return bootCmd
}
