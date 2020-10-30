package commands

import (
	"os"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"hyperspike.io/hyperctl/provider/aws"
)

func init() {
	rootCmd.AddCommand(credsCmd)
}
var clusterId string
var credsCmd = creds()

func creds() *cobra.Command {
	var command = &cobra.Command {
		Use: "creds",
		Short: "fetch the creds for a hyperspike cluster",
		Run: func(c *cobra.Command, args []string) {
			p := aws.Init("", "", "")
			p.Id = clusterId
			keys, err := p.FetchAdminKeys()
			if err != nil {
				return
			}

			f, err := os.Create("admin.conf")
			if err != nil {
				log.Errorf("failed to create %s, %v", "admin.conf", err)
				return
			}
			if _, err = f.WriteString(keys); err != nil {
				log.Errorf("failed to write to %s, %v", "admin.conf", err)
				if err := f.Close(); err != nil {
					log.Errorf("failed to close %s, %v", "admin.conf", err)
					return
				}
				return
			}
			if err := f.Close(); err != nil {
				log.Errorf("failed to close %s, %v", "admin.conf", err)
				return
			}
			log.Infof("successfully saved creds to 'admin.conf' for cluser %s", p.Id)
		},
	}

	command.Flags().StringVarP(&region,  "region",  "r", "us-east-2", "The region to deploy to")
	command.Flags().StringVarP(&clusterId,  "cluster",  "c", "", "Cluster ID to fetch")
	return command
}
