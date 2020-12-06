package commands

import (
	"os"
	"fmt"
	"github.com/spf13/cobra"
	"hyperspike.io/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(Clusters())
}

func Clusters() *cobra.Command {
	var clusters =  &cobra.Command {
		Use: "clusters",
		Short: "get a list of hyperspike clusters",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init("", "", "")
			list, err := p.List()
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to get cluster list, %v", err)
				os.Exit(1)
			}
			for _, c := range list {
				fmt.Println(c.Name(), c.State(), c.Age())
			}
			os.Exit(0)
		},
	}

	return clusters
}
