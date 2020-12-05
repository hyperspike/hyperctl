package commands

import (
	"os"
	"fmt"

	"github.com/spf13/cobra"
	"hyperspike.io/hyperctl/provider/aws"
)

func init() {
	destroyCmd.SetUsageTemplate("Usage:\n  hyperctl destroy [cluster-id] ...\n\nFlags:\n  -h, --help   help for destroy\n")
	rootCmd.AddCommand(destroyCmd)
}

var destroyCmd =  &cobra.Command {
	Use: "destroy",
	Short: "Destroy a hyperspike cluster",
	Run: func(c *cobra.Command, args []string) {
		p := aws.Init("", "", "")
		if len(args) == 0 {
			fmt.Printf("\033[1;31mError:\033[0m please give a cluster id\n\n")
			_ = c.Help()
			os.Exit(1)
		}
		p.Id = args[0]
		err := p.Destroy()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	},
}
