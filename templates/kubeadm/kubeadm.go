package kubeadm

import (
	"os"
	"io"
	log "github.com/sirupsen/logrus"
	"text/template"
	"crypto/rand"
	"encoding/hex"
	"bytes"
)

type KubeConf struct {
	IP            string
	CertKey       string
	LBDnsPriv     string
	Region        string
	ClusterName   string
	PodSubnet     string
	ServiceSubnet string
	KeyArn        string
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func New(clusterName string, ip string, region string, lbDnsPriv string, podSubnet string, serviceSubnet string, keyarn string) *KubeConf {
	key, err := randomHex(32)
	if err != nil {
		return nil
	}
	c := &KubeConf{
		IP: ip,
		CertKey: key,
		LBDnsPriv: lbDnsPriv,
		Region: region,
		ClusterName: clusterName,
		PodSubnet: podSubnet,
		ServiceSubnet: serviceSubnet,
		KeyArn: keyarn,
	}
	return c
}

func (c *KubeConf) KubeadmYaml() (string, error) {

	var err error
	kubeadm := template.New("kubeadm")
	kubeadm, err = kubeadm.Parse(`
---
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
    service-account-issuer: https://s3.{{ .Region }}.amazonaws.com/aws-irsa-oidc-{{ .ClusterName -}}/
    service-account-signing-key-file: /etc/kubernetes/pki/sa.key
    kubelet-preferred-address-types: Hostname,InternalDNS
certificatesDir: /etc/kubernetes/pki
clusterName: {{ .Region }}
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
kubernetesVersion: v1.18.8
networking:
  dnsDomain: {{ .ClusterName }}
  serviceSubnet: {{ .ServiceSubnet }}
  podSubnet: {{ .PodSubnet }}
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
clientConnection:
  acceptContentTypes: ""
  burst: 10
  contentType: application/vnd.kubernetes.protobuf
  kubeconfig: /var/lib/kube-proxy/kubeconfig.conf
  qps: 5
clusterCIDR: "{{ .PodSubnet -}}"
configSyncPeriod: 15m0s
conntrack:
  maxPerCore: 32768
  min: 131072
  tcpCloseWaitTimeout: 1h0m0s
  tcpEstablishedTimeout: 24h0m0s
enableProfiling: false
healthzBindAddress: 0.0.0.0:10256
hostnameOverride: ""
iptables:
  masqueradeAll: false
  masqueradeBit: 14
  minSyncPeriod: 0s
  syncPeriod: 30s
ipvs:
  excludeCIDRs: null
  minSyncPeriod: 0s
  scheduler: ""
  strictARP: false
  syncPeriod: 30s
kind: KubeProxyConfiguration
metricsBindAddress: 127.0.0.1:10249
mode: "ipvs"
nodePortAddresses: null
oomScoreAdj: -999
portRange: ""
udpIdleTimeout: 250ms
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
	defer file.Close()

	str, err := c.KubeadmYaml()
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
