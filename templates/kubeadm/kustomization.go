package kubeadm

import (
	"io"
	"os"
	log "github.com/sirupsen/logrus"
)

func (c *KubeConf) Kustomization() string {
	return `---
patchesJson6902:
- target:
    version: v1
    kind: Pod
    name: kube-apiserver
    namespace: kube-system
  path: api-secrets-provider.yaml
`
}
func (c *KubeConf) KustomizationFile(fn string) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Errorf("failed to create %s %v", fn, err)
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, c.Kustomization())
	if err != nil {
		log.Errorf("failed to write %s, %v", fn, err)
		return err
	}

	return file.Sync()
}

func (c *KubeConf) ApiSecretsProviderYaml() string {
	return `---
- op: add
  path: /spec/containers/0/volumeMounts/-
  value:
    mountPath: /etc/kubernetes/secrets.yaml
    name: secrets-config
    readOnly: true
- op: add
  path: /spec/containers/0/volumeMounts/-
  value:
    mountPath: /run/kmsplugin
    name: run-kmsplugin
- op: add
  path: /spec/volumes/-
  value:
    name: run-kmsplugin
    hostPath:
      path: /run/kmsplugin
      type: DirectoryOrCreate
- op: add
  path: /spec/volumes/-
  value:
    name: secrets-config
    hostPath:
      path: /etc/kubernetes/secrets.yaml
      type: FileOrCreate
`
}
func (c *KubeConf) ApiSecretsProviderFile(fn string) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Errorf("failed to create %s %v", fn, err)
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, c.ApiSecretsProviderYaml())
	if err != nil {
		log.Errorf("failed to write %s, %v", fn, err)
		return err
	}

	return file.Sync()
}
