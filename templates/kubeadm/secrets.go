package kubeadm

func (c *Conf) Secrets() string {
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
