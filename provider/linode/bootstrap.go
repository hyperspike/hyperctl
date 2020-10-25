package linode

import (
	"os"
	// "strings"
	// "regexp"
	// log "github.com/sirupsen/logrus"
	"context"
	"fmt"
	"encoding/base64"
	"github.com/linode/linodego"
	"golang.org/x/oauth2"

	"log"
	"net/http"
	"io/ioutil"

	//"k8s.io/client-go/kubernetes"
	//"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func Create() {
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
			writeKube(linodeClient, c.ID)
			fmt.Printf("cluster found exiting\n")
			os.Exit(0)
		}
	}
	cluster, err := linodeClient.CreateLKECluster(context.Background(), linodego.LKEClusterCreateOptions{
			Label: "internal-spooler",
			Region: "us-east",
			K8sVersion: "1.17",
			NodePools: []linodego.LKEClusterPoolCreateOptions{
				{
					Count: 2,
					Type: "g6-standard-2",
				},
			},
		})
	if err != nil {
		log.Fatal(err)
	}
	writeKube(linodeClient, cluster.ID)
	fmt.Printf("%v\n", cluster)
}

func writeKube(client linodego.Client, id int) {
	kConf, err := client.GetLKEClusterKubeconfig(context.Background(), id)
	if err != nil {
		log.Fatal(err)
	}
	kube, err := base64.StdEncoding.DecodeString(kConf.KubeConfig)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("kubeconfig", []byte(kube), 0600)
	if err != nil {
		log.Fatal(err)
	}
	config, err := clientcmd.NewClientConfigFromBytes([]byte(kube))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", config)
}

