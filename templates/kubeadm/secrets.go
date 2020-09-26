package kubeadm

import (
	"io"
	"os"
	"text/template"
	"bytes"
	log "github.com/sirupsen/logrus"
)

func (c *KubeConf) Secrets() string {
	return `---
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources:
  - secrets
  providers:
  - kms:
      name: aws-encryption-provider
      endpoint: unix:///run/kmsplugin/socket.sock
      cachesize: 1000
      timeout: 3s
  - identity: {}
`
}

func (c *KubeConf) SecretsFile(fn string) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Errorf("failed to create %s %v", fn, err)
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, c.Secrets())
	if err != nil {
		log.Errorf("failed to write %s, %v", fn, err)
		return err
	}

	return file.Sync()
}

func (c *KubeConf) SecretsProvider() (string, error) {
	var err error
	secrets := template.New("kubeadm")
	secrets, err = secrets.Parse(`---
apiVersion: v1
kind: Pod
metadata:
  name: aws-encryption-provider
  namespace: kube-system
spec:
  containers:
  - image: docker.io/graytshirt/aws-encryption-provider:0.0.1
    name: aws-encryption-provider
    command:
    - /aws-encryption-provider
    - --key={{ .KeyARN }}
    - --region={{ .Region }}
    - --listen=/run/kmsplugin/socket.sock
    - --health-port=:8083
    ports:
    - containerPort: 8083
      protocol: TCP
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8083
    volumeMounts:
    - mountPath: /run/kmsplugin
      name: run-kmsplugin
  hostNetwork: true
  volumes:
  - name: run-kmsplugin
    hostPath:
      path: /run/kmsplugin
      type: DirectoryOrCreate
`)

	if err != nil {
		return "", err
	}
	var str bytes.Buffer
	if err = secrets.Execute(&str, c); err != nil {
		return "", err
	}
	return str.String(), nil
}

func (c *KubeConf) SecretsProviderFile(fn string) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Errorf("failed to create %s %v", fn, err)
		return err
	}
	defer file.Close()

	str, err := c.SecretsProvider()
	if err != nil {
		return err
	}
	_, err = io.WriteString(file, str)
	if err != nil {
		log.Errorf("failed to write %s, %v", fn, err)
		return err
	}

	return file.Sync()
}
