package deployer

import (
	"context"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Deployer) ClusterAutoscaler() error {
	log.Infof("deploying cluster-autoscaler to %s", d.cluster)
	err := d.r.Create(context.Background(), clusterAutoscalerServiceAccount("arn:aws:iam::"+d.accountId+":role/cluster-autoscaler-"+d.cluster))
	if err != nil {
		log.Errorf("failed to create cluster-autoscaler service account, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), clusterAutoscalerClusterRole())
	if err != nil {
		log.Errorf("failed to create cluster-autoscaler cluster-role, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), clusterAutoscalerRole())
	if err != nil {
		log.Errorf("failed to create cluster-autoscaler role, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), clusterAutoscalerClusterRoleBinding())
	if err != nil {
		log.Errorf("failed to create cluster-autoscaler cluster-role-binding, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), clusterAutoscalerRoleBinding())
	if err != nil {
		log.Errorf("failed to create cluster-autoscaler role-binding, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), clusterAutoscalerDeployment(d.cluster))
	if err != nil {
		log.Errorf("failed to create cluster-autoscaler Deployment, %v", err)
		return err
	}

	return nil
}

func clusterAutoscalerServiceAccount(iamRole string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind: "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-autoscaler",
			Namespace: "kube-system",
			Labels: map[string]string {
				"k8s-addon": "cluster-autoscaler.addons.k8s.io",
				"k8s-app":   "cluster-autoscaler",
			},
			Annotations: map[string]string {
				"eks.amazonaws.com/role-arn": iamRole,
			},
		},
	}
}

func clusterAutoscalerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-autoscaler",
			Labels: map[string]string {
				"k8s-addon": "cluster-autoscaler.addons.k8s.io",
				"k8s-app":   "cluster-autoscaler",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"events",
					"endpoints",
				},
				Verbs: []string{
					"create",
					"patch",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"pods/eviction",
				},
				Verbs: []string{
					"create",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"pods/status",
				},
				Verbs: []string{
					"update",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"endpoints",
				},
				ResourceNames: []string{
					"cluster-autoscaler",
				},
				Verbs: []string{
					"get",
					"update",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"nodes",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"update",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"pods",
					"services",
					"replicationcontrollers",
					"persistentvolumeclaims",
					"persistentvolumes",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					"extensions",
				},
				Resources: []string{
					"replicasets",
					"daemonsets",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					"policy",
				},
				Resources: []string{
					"poddisruptionbudgets",
				},
				Verbs: []string{
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					"apps",
				},
				Resources: []string{
					"statefulsets",
					"replicasets",
					"daemonsets",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					"storage.k8s.io",
				},
				Resources: []string{
					"storageclasses",
					"csinodes",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					"batch",
					"extensions",
				},
				Resources: []string{
					"jobs",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
					"patch",
				},
			},
			{
				APIGroups: []string{
					"coordination.k8s.io",
				},
				Resources: []string{
					"leases",
				},
				Verbs: []string{
					"create",
				},
			},
			{
				APIGroups: []string{
					"coordination.k8s.io",
				},
				Resources: []string{
					"leases",
				},
				ResourceNames: []string{
					"cluster-autoscaler",
				},
				Verbs: []string{
					"get",
					"update",
				},
			},
		},
	}
}

func clusterAutoscalerRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind: "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-autoscaler",
			Labels: map[string]string {
				"k8s-addon": "cluster-autoscaler.addons.k8s.io",
				"k8s-app":   "cluster-autoscaler",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"configmaps",
				},
				Verbs: []string{
					"create",
					"list",
					"watch",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"configmaps",
				},
				ResourceNames: []string{
					"cluster-autoscaler-status",
					"cluster-autoscaler-priority-expander",
				},
				Verbs: []string{
					"delete",
					"get",
					"update",
					"watch",
				},
			},
		},
	}
}

func clusterAutoscalerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-autoscaler",
			Labels: map[string]string {
				"k8s-addon": "cluster-autoscaler.addons.k8s.io",
				"k8s-app":   "cluster-autoscaler",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "cluster-autoscaler",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "cluster-autoscaler",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}

func clusterAutoscalerRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-autoscaler",
			Labels: map[string]string {
				"k8s-addon": "cluster-autoscaler.addons.k8s.io",
				"k8s-app":   "cluster-autoscaler",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "Role",
			Name: "cluster-autoscaler",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "cluster-autoscaler",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}

func clusterAutoscalerDeployment(name string) *appsv1.Deployment {
	one := int32(1)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-autoscaler",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app": "cluster-autoscaler",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"app": "cluster-autoscaler",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"app": "cluster-autoscaler",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "cluster-autoscaler",
					Containers: []corev1.Container{
						{
							Name: "cluster-autoscaler",
							Image: "k8s.gcr.io/autoscaling/cluster-autoscaler:v1.20.0",
							Command: []string{
								"./cluster-autoscaler",
								"--v=4",
								"--stderrthreshold=info",
								"--cloud-provider=aws",
								"--skip-nodes-with-local-storage=false",
								"--expander=least-waste",
								"--node-group-auto-discovery=asg:tag=kubernetes.io/cluster-autoscaler/enabled,kubernetes.io/cluster/"+name,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name: "ssl-certs",
									MountPath: "/etc/ssl/certs/ca-bundle.crt",
									ReadOnly: true,
								},
							},
						},
					},
					Tolerations: []corev1.Toleration{
						{
							Key: "node-role.kubernetes.io/master",
							Effect: "NoSchedule",
						},
					},
					NodeSelector: map[string]string{
						"node-role.kubernetes.io/master": "",
					},
					Volumes: []corev1.Volume{
						{
							Name: "ssl-certs",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/ssl/certs/ca-bundle.crt",
								},
							},
						},
					},
				},
			},
		},
	}
}
