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
			fmt.Printf(`  Hyperctl Version Info

    Hyperspike: %s
    Go:         %s
    Kubernetes: %s
    Cilium:     %s

`, hyperctl.Version, runtime.Version(), hyperctl.KubeVersion, hyperctl.CiliumVersion)
		},
	}

	return ver
}
