package commands

import (
	"github.com/spf13/cobra"
	/* "os"
	// "strings"
	// "regexp"
	// log "github.com/sirupsen/logrus"
	"context"
	"fmt"
	"github.com/linode/linodego"
	"golang.org/x/oauth2"

	"log"
	"net/http" */
)

func init() {
	rootCmd.AddCommand(destroyCmd)
}

var destroyCmd =  &cobra.Command {
	Use: "destroy",
	Short: "Destroy A Linode LKE Cluster",
	Run: func(c *cobra.Command, args []string) {
		/*
		apiKey, ok := os.LookupEnv("LINODE_TOKEN")
		if !ok {
		log.Fatal("Could not find LINODE_TOKEN, please assert it is set.")
		}
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: apiKey})

		oauth2Client := &http.Client{
			Transport: &oauth2.Transport{
				Source: tokenSource,
			},
		}

		linodeClient := linodego.NewClient(oauth2Client)
		linodeClient.SetDebug(true)

		clusters, err := linodeClient.ListLKEClusters(context.Background(), nil)
		if err != nil {
			log.Fatal(err)
		}
		for _, c := range clusters {
			fmt.Printf("%v\n", c)
			if c.Label == "internal-spooler" {
				fmt.Printf("cluster found destroying\n")
				err = linodeClient.DeleteLKECluster(context.Background(), c.ID)
				if err != nil {
					log.Fatal(err)
				}
				os.Exit(0)
			}
		}
		fmt.Printf("Cluster not found\n")
		os.Exit(1)
		*/
	},
}
