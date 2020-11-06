package deployer

import (
	"context"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/api/resource"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	if err := d.r.Create(context.Background(), ciliumClusterRole()) ; err != nil {
		log.Errorf("failed to create cilium cluster role, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), ciliumOperatorClusterRole()) ; err != nil {
		log.Errorf("failed to create cilium operator cluster role, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), ciliumClusterRoleBinding()) ; err != nil {
		log.Errorf("failed to create cilium cluster role binding, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), ciliumOperatorClusterRoleBinding()) ; err != nil {
		log.Errorf("failed to create cilium operator cluster role binding, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), ciliumConfigMap(d.pods, d.cluster)) ; err != nil {
		log.Errorf("failed to create cilium configmap, %v", err)
		return err
	}

	if err := d.ciliumDaemonSet(); err != nil {
		return err
	}
	if err := d.ciliumOperatorDeployment(); err != nil {
		return err
	}

	return nil
}

func ptrToBool(b bool) *bool {
	return &b
}
func ptrToInt64(i int64) *int64 {
	return &i
}
func ptrToInt32(i int32) *int32 {
	return &i
}

func ciliumConfigMap(pods, cluster string) *corev1.ConfigMap { // {{{
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
			"enable-host-firewall": "false",
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
			"hubble-metrics-server": ":9092",
			"hubble-metrics": "dns:query;ignoreAAAA,drop,tcp,flow,port-distribution,icmp,http",
			"hubble-listen-address": ":4244",
			"ipam": "eni",
			"cluster-pool-ipv4-cidr": pods,
			"cluster-pool-ipv4-mask-size": "24",
			"disable-cnp-status-updates": "true",
		},
	}
}
// }}}

func (d *Deployer) ciliumServiceAccount(name string) error { // {{{
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
	err := d.r.Create(context.Background(), sa)
	if err != nil {
		log.Errorf("failed to create %s service account, %v", name, err)
		return err
	}
	return nil
}
// }}}

func (d *Deployer) ciliumDaemonSet() error { // {{{
	requestCpu, _ := resource.ParseQuantity("100m")
	requestMemory, _ := resource.ParseQuantity("100Mi")
	dirCreate := corev1.HostPathDirectoryOrCreate
	fileCreate := corev1.HostPathFileOrCreate
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
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(2)},
				},
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
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
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{
												Key: "k8s-app",
												Operator: "In",
												Values: []string{
													"cilium",
												},
											},
										},
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					ServiceAccountName: "cilium",
					HostNetwork: true,
					RestartPolicy: "Always",
					PriorityClassName: "system-node-critical",
					TerminationGracePeriodSeconds: ptrToInt64(int64(1)),
					Containers: []corev1.Container{
						{
							Name: "cilium-agent",
							Image: "docker.io/cilium/cilium:"+d.ciliumVersion,
							Command: []string{
								"cilium-agent",
							},
							Args: []string{
								"--config-dir=/tmp/cilium/config-map",
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Host: "127.0.0.1",
										Path: "/healthz",
										Port: intstr.IntOrString{Type: intstr.Int, IntVal: int32(9876)},
										Scheme: "HTTP",
									},
								},
								FailureThreshold:    int32(10),
								InitialDelaySeconds: int32(120),
								PeriodSeconds:       int32(30),
								SuccessThreshold:    int32(1),
								TimeoutSeconds:      int32(5),
							},
							Env: []corev1.EnvVar{
								{
									Name: "K8S_NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "spec.nodeName",
										},
									},
								},
								{
									Name: "CILIUM_K8S_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "metadata.namespace",
										},
									},
								},
								{
									Name: "CILIUM_FLANNEL_MASTER_DEVICE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "flannel-master-device",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "CILIUM_FLANNEL_UNISTALL_ON_EXIT",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "flannel-uninstall-on-exit",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "CILIUM_CLUSTERMESH_CONFIG",
									Value: "/var/lib/cilium/clustermesh/",
								},
								{
									Name: "CILIUM_CNI_CHAINING_MODE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "cilium-chaining-mode",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "CILIUM_CUSTOM_CNI_CONF",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "cilium-cni-conf",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "KUBERNETES_SERVICE_HOST",
									Value: d.endpoint,
								},
								{
									Name: "KUBERNETES_SERVICE_PORT",
									Value: "6443",
								},
							},
							Lifecycle: &corev1.Lifecycle{
								PostStart: &corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"/cni-install.sh",
											"--enable-debug=false",
										},
									},
								},
								PreStop: &corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"/cni-uninstall.sh",
										},
									},
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 9091,
									HostPort:      9091,
									Protocol:      "TCP",
									Name:          "prometheus",
								},
								{
									ContainerPort: 9092,
									HostPort:      9092,
									Protocol:      "TCP",
									Name:          "hubble-metrics",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptrToBool(true),
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
										"SYS_MODULE",
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name: "bpf-maps",
									MountPath: "/sys/fs/bpf",
								},
								{
									Name: "cilium-run",
									MountPath: "/var/run/cilium",
								},
								{
									Name: "cni-path",
									MountPath: "/host/opt/cni/bin",
								},
								{
									Name: "etc-cni-netd",
									MountPath: "/host/etc/cni/net.d",
								},
								{
									Name: "clustermesh-secrets",
									MountPath: "/var/lib/cilium/clustermesh",
									ReadOnly: true,
								},
								{
									Name: "cilium-config-path",
									MountPath: "/tmp/cilium/config-map",
									ReadOnly: true,
								},
								{
									Name: "lib-modules",
									MountPath: "/lib/modules",
									ReadOnly: true,
								},
								{
									Name: "xtables-lock",
									MountPath: "/run/xtables.lock",
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									"cpu":    requestCpu,
									"memory": requestMemory,
								},
							},
						},
					},
					InitContainers: []corev1.Container{
						{
							Name: "clean-cilium-state",
							Image: "docker.io/cilium/cilium:"+d.ciliumVersion,
							Command: []string{
								"/init-container.sh",
							},
							Env: []corev1.EnvVar{
								{
									Name: "CILIUM_ALL_STATE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "clean-cilium-state",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "CILIUM_BPF_STATE",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "clean-cilium-bpf-state",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "CILIUM_WAIT_BPF_MOUNT",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "wait-bpf-mount",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "KUBERNETES_SERVICE_HOST",
									Value: d.endpoint,
								},
								{
									Name: "KUBERNETES_SERVICE_PORT",
									Value: "6443",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptrToBool(true),
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"NET_ADMIN",
										"sys_module",
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name: "bpf-maps",
									MountPath: "/sys/fs/bpf",
								},
								{
									Name: "cilium-run",
									MountPath: "/var/run/cilium",
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "cilium-run",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/cilium",
									Type: &dirCreate,
								},
							},
						},
						{
							Name: "bpf-maps",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys/fs/bpf",
									Type: &dirCreate,
								},
							},
						},
						{
							Name: "cni-path",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/opt/bin/cni",
									Type: &dirCreate,
								},
							},
						},
						{
							Name: "etc-cni-netd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/cni/net.d",
									Type: &dirCreate,
								},
							},
						},
						{
							Name: "lib-modules",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/lib/modules",
									Type: &dirCreate,
								},
							},
						},
						{
							Name: "xtables-lock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/run/xtables.lock",
									Type: &fileCreate,
								},
							},
						},
						{
							Name: "clustermesh-secrets",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "cilium-clustermesh",
									Optional: ptrToBool(true),
									DefaultMode: ptrToInt32(int32(420)),
								},
							},
						},
						{
							Name: "cilium-config-path",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "cilium-config",
									},
								},
							},
						},
					},
				},
			},
		},
		
	}
	if err := d.r.Create(context.Background(), ds); err != nil {
		log.Errorf("failed to create cilium-agent daemonset, %v", err)
		return err
	}
	return nil
}
// }}}

func (d *Deployer) ciliumOperatorDeployment() error { // {{{

	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-operator",
			Namespace: "kube-system",
			Labels: map[string]string {
				"io.cilium/app": "operator",
				"name": "cilium-operator",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptrToInt32(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"io.cilium/app": "operator",
					"name": "cilium-operator",
				},
			},
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(1)},
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(1)},
				},
				Type: appsv1.RollingUpdateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"io.cilium/app": "operator",
						"name": "cilium-operator",
					},
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{
												Key: "io.cilium/app",
												Operator: "In",
												Values: []string{
													"operator",
												},
											},
										},
									},
									TopologyKey: "kubernetes.io/hostname",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name: "cilium-operator",
							Image: "docker.io/cilium/operator-aws:"+d.ciliumVersion,
							Env: []corev1.EnvVar{
								{
									Name: "K8S_NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "spec.nodeName",
										},
									},
								},
								{
									Name: "CILIUM_K8S_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "metadata.namespace",
										},
									},
								},
								{
									Name: "CILIUM_DEBUG",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-config",
											},
											Key: "debug",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "AWS_ACCESS_KEY_ID",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-aws",
											},
											Key: "AWS_ACCESS_KEY_ID",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "AWS_SECRET_ACCESS_KEY",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-aws",
											},
											Key: "AWS_SECRET_ACCESS_KEY",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "AWS_DEFAULT_REGION",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "cilium-aws",
											},
											Key: "AWS_DEFAULT_REGION",
											Optional: ptrToBool(true),
										},
									},
								},
								{
									Name: "KUBERNETES_SERVICE_HOST",
									Value: d.endpoint,
								},
								{
									Name: "KUBERNETES_SERVICE_PORT",
									Value: "6443",
								},
								{
									Name: "HOME",
									Value: "/tmp",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 6942,
									HostPort:      6942,
									Protocol:      "TCP",
									Name:          "prometheus",
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Host: "127.0.0.1",
										Path: "/healthz",
										Port: intstr.IntOrString{Type: intstr.Int, IntVal: int32(9234)},
										Scheme: "HTTP",
									},
								},
								InitialDelaySeconds: int32(60),
								PeriodSeconds:       int32(10),
								TimeoutSeconds:      int32(3),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name: "cilium-config-path",
									MountPath: "/tmp/cilium/config-map",
									ReadOnly: true,
								},
							},
						},
					},
					HostNetwork: true,
					RestartPolicy: "Always",
					PriorityClassName: "system-cluster-critical",
					ServiceAccountName: "cilium-operator",
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "cilium-config-path",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "cilium-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if err := d.r.Create(context.Background(), dep); err != nil {
		log.Errorf("failed to create cilium-operator deployment , %v", err)
		return err
	}
	return nil
}
// }}}

func ciliumClusterRole() *rbacv1.ClusterRole { // {{{
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"networking.k8s.io",
				},
				Resources: []string{
					"networkpolicies",
				},
			},
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"discovery.k8s.io",
				},
				Resources: []string{
					"endpointslices",
				},
			},
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"namespaces",
					"services",
					"nodes",
					"endpoints",
				},
			},
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
					"update",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"nodes",
					"pods",
				},
			},
			{
				Verbs: []string{
					"patch",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"nodes",
					"nodes/status",
				},
			},
			{
				Verbs: []string{
					"create",
					"get",
					"list",
					"watch",
					"update",
				},
				APIGroups: []string{
					"apiextensions.k8s.io",
				},
				Resources: []string{
					"customresourcedefinitions",
				},
			},
			{
				Verbs: []string{
					"*",
				},
				APIGroups: []string{
					"cilium.io",
				},
				Resources: []string{
					"ciliumnetworkpolicies",
					"ciliumnetworkpolicies/status",
					"ciliumclusterwidenetworkpolicies",
					"ciliumclusterwidenetworkpolicies/status",
					"ciliumendpoints",
					"ciliumendpoints/status",
					"ciliumnodes",
					"ciliumnodes/status",
					"ciliumidentities",
					"ciliumidentities/status",
				},
			},
			
		},
	}
}
// }}}

func ciliumOperatorClusterRole() *rbacv1.ClusterRole { // {{{
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-operator",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
					"delete",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"pods",
				},
			},
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"discovery.k8s.io",
				},
				Resources: []string{
					"endpointslices",
				},
			},
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"namespaces",
					"services",
					"endpoints",
				},
			},
			{
				Verbs: []string{
					"*",
				},
				APIGroups: []string{
					"cilium.io",
				},
				Resources: []string{
					"ciliumnetworkpolicies",
					"ciliumnetworkpolicies/status",
					"ciliumclusterwidenetworkpolicies",
					"ciliumclusterwidenetworkpolicies/status",
					"ciliumendpoints",
					"ciliumendpoints/status",
					"ciliumnodes",
					"ciliumnodes/status",
					"ciliumidentities",
					"ciliumidentities/status",
				},
			},
			{
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"apiextensions.k8s.io",
				},
				Resources: []string{
					"customresourcedefinitions",
				},
			},
			{
				Verbs: []string{
					"create",
					"update",
					"get",
				},
				APIGroups: []string{
					"coordination.k8s.io",
				},
				Resources: []string{
					"leases",
				},
			},
		},
	}
}
// }}}

func ciliumClusterRoleBinding() *rbacv1.ClusterRoleBinding { // {{{
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "cilium",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "cilium",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}
// }}}

func ciliumOperatorClusterRoleBinding() *rbacv1.ClusterRoleBinding { // {{{
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-operator",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "cilium-operator",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "cilium-operator",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}
// }}}
