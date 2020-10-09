package commands

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(Clusters())
}

func Clusters() *cobra.Command {
	var clusters =  &cobra.Command {
		Use: "clusters",
		Short: "get a list of hyperspike clusters",
		Run: func(c *cobra.Command, args []string) {
		},
	}

	return clusters
}
