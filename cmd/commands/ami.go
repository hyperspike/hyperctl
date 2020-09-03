package commands

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"hyperspike.io/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(AMI())
}

func AMI() *cobra.Command {
	var ami =  &cobra.Command {
		Use: "ami",
		Short: "print AMIs",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init("us-east-2", "")
			ami, _ := p.SearchAMI("751883444564", map[string]string{"name":"hyperspike-*"})
			log.WithFields(log.Fields{"ami": ami}).Info("fetched latest AMI")
		},
	}

	return ami
}
