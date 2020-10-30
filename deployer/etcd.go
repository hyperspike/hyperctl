package deployer

import (
	"context"
	"io/ioutil"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Deployer) EtcdCerts() error {
	certFile := "/etc/kubernetes/pki/etcd/healthcheck-client.crt"
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return errors.WithMessagef(err, "error reading cert file %s", certFile)
	}
	keyFile := "/etc/kubernetes/pki/etcd/healthcheck-client.key"
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return errors.WithMessagef(err, "error reading cert file %s", keyFile)
	}

	if err := d.r.Create(context.TODO(), namespace("monitoring")); err != nil {
		log.Errorf("failed to monitoring namesapce, %v", err)
		return err
	}
	if err := d.r.Create(context.TODO(), createTlsSecret(cert, key, "etcd-client", "monitoring")); err != nil {
		log.Errorf("failed to create etcd secrets, %v", err)
		return err
	}

	return nil
}

func namespace(name string) *corev1.Namespace {
	return &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind: "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "monitoring",
		},
	}
}
