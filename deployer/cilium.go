package deployer

import (
	"context"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Deployer) Cilium() error {
	log.Infof("deploying cilium to %s", d.cluster)
	if err := d.ciliumServiceAccount("cilium-operator") ; err != nil {
		return err
	}
	if err := d.ciliumServiceAccount("cilium") ; err != nil {
		return err
	}
	if err := d.ciliumServiceAccount("hubble-relay") ; err != nil {
		return err
	}
	if err := d.ciliumServiceAccount("hubble-ui") ; err != nil {
		return err
	}
	err := d.r.Create(context.TODO(), ciliumConfigMap(d.pods, d.cluster))
	if err != nil {
		log.Errorf("failed to create cilium configmap, %v", err)
		return err
	}

	if err = d.ciliumDaemonSet(); err != nil {
		return err
	}

	return nil
}

func ciliumConfigMap(pods, cluster string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind: "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-config",
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"identity-allocation-mode": "crd",
			"debug": "false",
			"prometheus-serve-addr": ":9091",
			"operator-prometheus-serve-addr": ":6942",
			"enable-metrics": "true",
			"enable-ipv4": "true",
			"enable-ipv6": "false",
			"enable-bpf-clock-probe": "true",
			"monitor-aggregation": "medium",
			"monitor-aggregation-interval": "5s",
			"monitor-aggregation-flags": "all",
			"bpf-policy-map-max": "16384",
			"bpf-map-dynamic-size-ratio": "0.0025",
			"preallocate-bpf-maps": "false",
			"sidecar-istio-proxy-image": "cilium/istio_proxy",
			"tunnel": "disabled",
			"cluster-name": cluster,
			"enable-endpoint-routes": "true",
			"auto-create-cilium-node-resource": "true",
			"blacklist-conflicting-routes": "false",
			"wait-bpf-mount": "false",
			"masquerade": "true",
			"enable-bpf-masquerade": "true",
			"enable-xt-socket-fallback": "true",
			"install-iptables-rules": "true",
			"auto-direct-node-routes": "true",
			"native-routing-cidr": pods,
			"enable-host-firewall": "true",
			"kube-proxy-replacement":  "probe",
			"enable-host-reachable-services": "true",
			"enable-health-check-nodeport": "true",
			"node-port-bind-protection": "true",
			"enable-auto-protect-node-port-range": "true",
			"enable-session-affinity": "true",
			"k8s-require-ipv4-pod-cidr": "true",
			"k8s-require-ipv6-pod-cidr": "false",
			"enable-endpoint-health-checking": "true",
			"enable-well-known-identities": "false",
			"enable-remote-node-identity": "true",
			"operator-api-serve-addr": "127.0.0.1:9234",
			"enable-hubble": "true",
			"hubble-socket-path":  "/var/run/cilium/hubble.sock",
			"hubble-metrics-server": ":9091",
			"hubble-metrics": "dns:query;ignoreAAAA,drop,tcp,flow,port-distribution,icmp,http",
			"hubble-listen-address": ":4244",
			"ipam": "cluster-pool",
			"cluster-pool-ipv4-cidr": pods,
			"cluster-pool-ipv4-mask-size": "24",
			"disable-cnp-status-updates": "true",
		},
	}
}

func (d *Deployer) ciliumServiceAccount(name string) error {
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind: "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Namespace: "kube-system",
		},
	}
	err := d.r.Create(context.TODO(), sa)
	if err != nil {
		log.Errorf("failed to create %s service account, %v", name, err)
		return err
	}
	return nil
}

func (d *Deployer) ciliumDaemonSet() error {
	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
			Namespace: "kube-system",
			Labels: map[string]string {
				"k8s-app": "cilium",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"k8s-app": "cilium",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"k8s-app": "cilium",
					},
					Annotations: map[string]string {
						"scheduler.alpha.kubernetes.io/critical-pod": "",
					},
				},
				Spec: corev1.PodSpec{
					Affinity: nil,
					ServiceAccountName: "",
					HostNetwork: true,
					Containers: []corev1.Container{
						{
							Name: "cilium-agent",
							Image: "docker.io/cilium/cilium:v1.8.4",
							Command: []string{
								"cilium-agent",
							},
							Args: []string{
								"--config-dir=/tmp/cilium/config-map",
							},
							Env: []corev1.EnvVar{
								{
									Name: "KUBERNETES_PORT_6443_TCP",
									Value: "tcp://"+d.endpoint+":6443",
								},
								{
									Name: "KUBERNETES_SERVICE_PORT",
									Value: "6443",
								},
								{
									Name: "KUBERNETES_PORT",
									Value: "tcp://"+d.endpoint+":6443",
								},
								{
									Name: "KUBERNETES_SERVICE_HOST",
									Value: d.endpoint,
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key:  "node.cloudprovider.kubernetes.io/uninitialized",
							Value: "true",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key: "node-role.kubernetes.io/master",
							Effect: corev1.TaintEffectNoSchedule,
						},
						{
							Key: "node.kubernetes.io/not-ready",
							Effect: corev1.TaintEffectNoSchedule,
						},
					},
					NodeSelector: map[string]string{
						"node-role.kubernetes.io/master": "",
					},
				},
			},
		},
		
	}
	if err := d.r.Create(context.TODO(), ds); err != nil {
		log.Errorf("failed to create cilium-agent daemonset, %v", err)
		return err
	}
	return nil
}
