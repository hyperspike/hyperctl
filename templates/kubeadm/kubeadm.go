package kubeadm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
	"text/template"
)

type KubeConf struct {
	IP            string
	CertKey       string
	LBDnsPriv     string
	Region        string
	ClusterName   string
	DNSName       string
	PodSubnet     string
	ServiceSubnet string
	KeyArn        string
	KubeVersion   string
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func New(clusterName, ip, region, lbDnsPriv, podSubnet, serviceSubnet, keyarn, kubever string) *KubeConf {
	var key, err = randomHex(32)
	if err != nil {
		return nil
	}
	var c = &KubeConf{
		IP:            ip,
		CertKey:       key,
		LBDnsPriv:     lbDnsPriv,
		Region:        region,
		ClusterName:   clusterName,
		DNSName:       strings.ReplaceAll(clusterName, "-", "."),
		PodSubnet:     podSubnet,
		ServiceSubnet: serviceSubnet,
		KeyArn:        keyarn,
		KubeVersion:   kubever,
	}
	return c
}

func (c *KubeConf) KubeadmYaml() (string, error) {

	var err error
	kubeadm := template.New("kubeadm")
	kubeadm, err = kubeadm.Parse(`---
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: {{ .IP }}
  bindPort: 6443
certificateKey: {{ .CertKey }}
nodeRegistration:
  criSocket: /run/crio/crio.sock
  kubeletExtraArgs:
    feature-gates: gates=CSINodeInfo=true,CSIDriverRegistry=true,CSIBlockVolume=true
    cloud-provider: external
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
apiServer:
  timeoutForControlPlane: 4m0s
  certSANs:
  - {{ .IP }}
  - {{ .LBDnsPriv }}
  extraArgs:
    cloud-provider: external
    feature-gates: CSINodeInfo=true,CSIDriverRegistry=true,CSIBlockVolume=true,VolumeSnapshotDataSource=true
    encryption-provider-config: /etc/kubernetes/secrets.yaml
    api-audiences: sts.amazonaws.com
    service-account-issuer: https://s3.{{ .Region }}.amazonaws.com/{{ .ClusterName -}}-irsa/
    service-account-signing-key-file: /etc/kubernetes/pki/sa.key
    kubelet-preferred-address-types: Hostname,InternalDNS
certificatesDir: /etc/kubernetes/pki
clusterName: {{ .ClusterName }}
controlPlaneEndpoint: {{ .LBDnsPriv -}}:6443
controllerManager:
  extraArgs:
    cloud-provider: external
    bind-address: 0.0.0.0
scheduler:
  extraArgs:
    bind-address: 0.0.0.0
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: k8s.gcr.io
kubernetesVersion: {{ .KubeVersion }}
networking:
  dnsDomain: {{ .DNSName }}
  serviceSubnet: {{ .ServiceSubnet }}
  podSubnet: {{ .PodSubnet }}
`)

	if err != nil {
		return "", err
	}
	var str bytes.Buffer
	if err = kubeadm.Execute(&str, c); err != nil {
		return "", err
	}
	return str.String(), nil
}

func (c *KubeConf) KubeadmFile(fn string) error {
	file, err := os.Create(fn)
	if err != nil {
		log.Errorf("failed to create %s %v", fn, err)
		return err
	}

	str, err := c.KubeadmYaml()
	if err != nil {
		if err := file.Close(); err != nil {
			log.Errorf("failed to close %s, %v", fn, err)
		}
		return err
	}
	_, err = io.WriteString(file, str)
	if err != nil {
		if err := file.Close(); err != nil {
			log.Errorf("failed to close %s, %v", fn, err)
		}
		log.Errorf("failed to write %s, %v", fn, err)
		return err
	}

	if err := file.Sync(); err != nil {
		if err := file.Close(); err != nil {
			log.Errorf("failed to close %s, %v", fn, err)
		}
		log.Errorf("failed to sync %s, %v", fn, err)
		return err
	}
	return file.Close()
}
