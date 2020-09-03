package kubeadm


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
