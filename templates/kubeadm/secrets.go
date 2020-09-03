package kubeadm

import (
	"text/template"
	"bytes"
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
