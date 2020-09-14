package commands

import (
	"os"
	"github.com/spf13/cobra"
	log "github.com/sirupsen/logrus"
	"hyperspike.io/hyperctl/provider/aws"
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
			if provider == "aws" {
				p := aws.Init("", "", "")
				err := p.Boot()
				if err != nil {
					os.Exit(1)
				}
			} else {
				log.Fatalf("provider %s not supported at this time\n", provider)
			}
		},
	}

	bootCmd.Flags().StringVarP(&provider, "provider", "p", "aws", "the cloud provider")
	return bootCmd
}
