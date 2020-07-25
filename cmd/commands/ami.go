package commands

import (
	"fmt"
	"github.com/spf13/cobra"
	"hyperspike.io/eng/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(AMI())
}

func AMI() *cobra.Command {
	var ami =  &cobra.Command {
		Use: "ami",
		Short: "print AMIs",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init()
			ami, _ := p.SearchAMI("751883444564", map[string]string{"tag:Name":"hyperspike-*"})
			fmt.Println("the latests AMI is", ami)

		},
	}

	return ami
}
