package deployer

import (
	"context"
	"k8s.io/client-go/rest"
	"k8s.io/apimachinery/pkg/runtime"
	// "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"k8s.io/client-go/kubernetes/scheme"
)

type Deployer struct {
	r client.Client
}

func New() (*Deployer, error) {
	_ = context.Background()
	cfg, err := clientcmd.BuildConfigFromFlags("", "/etc/kubernetes/admin.conf")
	if err != nil {
		log.Errorf("failed to read kube-config, %v", err)
		return nil, err
	}

	kconfig := rest.CopyConfig(cfg)

	s := runtime.NewScheme()
	_ = scheme.AddToScheme(s)

	var c Deployer
	c.r, err = client.New(kconfig, client.Options{
		Scheme: s,
	})
	if err != nil {
		log.Errorf("failed to build controller-runtime client, %v", err)
		return nil, err
	}

	return &c, nil
}
