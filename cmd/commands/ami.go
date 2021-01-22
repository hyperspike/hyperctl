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
			p := aws.Init(region, "", "")
			ami, name, desc, _ := p.SearchAMI("751883444564", map[string]string{"name":"hyperspike-*"})
			log.WithFields(log.Fields{"ami": ami, "name": name,}).Infof("fetched latest AMI (%s)", desc)
		},
	}

	ami.Flags().StringVarP(&region,  "region",  "r", "", "The region to use")

	return ami
}
