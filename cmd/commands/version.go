package commands

import (
	"fmt"
	"runtime"
	"github.com/spf13/cobra"
	"hyperspike.io/hyperctl"
)

func init() {
	rootCmd.AddCommand(Version())
}

func Version() *cobra.Command {
	var ver =  &cobra.Command {
		Use: "version",
		Short: "Hyperctl Version",
		Run: func(c *cobra.Command, args []string) {
			fmt.Printf("Hyperctl Version: %s\n  Go Version: %s\n  Kubernetes Version: %s\n", hyperctl.Version, runtime.Version(), hyperctl.KubeVersion)
		},
	}

	return ver
}
