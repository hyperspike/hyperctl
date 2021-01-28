package commands

import (
	"os"
	"github.com/spf13/cobra"
	log "github.com/sirupsen/logrus"
	"hyperspike.io/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(NodeCommand())
}

var provider string

func NodeCommand() *cobra.Command {
	var nodeCmd =  &cobra.Command {
		Use: "node",
		Short: "boot a node into the cluster",
		Hidden: true,
		Run: func(c *cobra.Command, args []string) {
			logFile, err := os.OpenFile("/var/log/hyperspike.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			 }
			defer logFile.Close()
			log.SetFormatter(&log.JSONFormatter{})
			log.SetOutput(logFile)
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

	nodeCmd.Flags().StringVarP(&provider, "provider", "p", "aws", "the cloud provider")
	return nodeCmd
}
