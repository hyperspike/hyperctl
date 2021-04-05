package deployer

import (
	"context"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Deployer) Hypergrade() error {
	log.Infof("deploying hypergrade to %s", d.cluster)
	if err := d.r.Create(context.Background(), hypergradeClusterRole()); err != nil {
		log.Errorf("failed to create hyperspike configmap, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), hyperspikeConfigMap(d.accountId)); err != nil {
		log.Errorf("failed to crate hyperspike config map, %v", err)
		return err
	}
	err := d.r.Create(context.Background(), hypergradeServiceAccount("arn:aws:iam::"+d.accountId+":role/hypergrade-"+d.cluster))
	if err != nil {
		log.Errorf("failed to create hypergrade service account, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), hypergradeClusterRole())
	if err != nil {
		log.Errorf("failed to create hypergrade cluster-role, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), hypergradeRole())
	if err != nil {
		log.Errorf("failed to create hypergrade role, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), hypergradeClusterRoleBinding())
	if err != nil {
		log.Errorf("failed to create hypergrade cluster-role-binding, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), hypergradeRoleBinding())
	if err != nil {
		log.Errorf("failed to create hypergrade role-binding, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), hypergradeDeployment(d.cluster))
	if err != nil {
		log.Errorf("failed to create hypergrade Deployment, %v", err)
		return err
	}

	return nil
}

func hyperspikeConfigMap(clusterName string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind: "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hyperspike",
			Namespace: "kube-system",
			Labels: map[string]string {
				"k8s-addon": "hypergrade.addons.k8s.io",
				"k8s-app":   "hypergrade",
			},
		},
		Data: map[string]string {
			"cluster-id": clusterName,
		},
	}
}

func hypergradeServiceAccount(iamRole string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind: "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hypergrade",
			Namespace: "kube-system",
			Labels: map[string]string {
				"k8s-addon": "hypergrade.addons.k8s.io",
				"k8s-app":   "hypergrade",
			},
			Annotations: map[string]string {
				"eks.amazonaws.com/role-arn": iamRole,
			},
		},
	}
}

func hypergradeClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hypergrade",
			Labels: map[string]string {
				"k8s-addon": "hypergrade.addons.k8s.io",
				"k8s-app":   "hypergrade",
			},
		},
		Rules: []rbacv1.PolicyRule{
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
					"configmaps",
				},
				ResourceNames: []string{
					"hypergrade",
				},
				Verbs: []string{
					"get",
					"update",
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
					"hypergrade",
				},
				Verbs: []string{
					"get",
					"update",
				},
			},
		},
	}
}

func hypergradeRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind: "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hypergrade",
			Namespace: "kube-system",
			Labels: map[string]string {
				"k8s-addon": "hypergrade.addons.k8s.io",
				"k8s-app":   "hypergrade",
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
					"hypergrade-status",
					"hypergrade-priority-expander",
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

func hypergradeClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hypergrade",
			Labels: map[string]string {
				"k8s-addon": "hypergrade.addons.k8s.io",
				"k8s-app":   "hypergrade",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "hypergrade",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "hypergrade",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}

func hypergradeRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hypergrade",
			Namespace: "kube-system",
			Labels: map[string]string {
				"k8s-addon": "hypergrade.addons.k8s.io",
				"k8s-app":   "hypergrade",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "Role",
			Name: "hypergrade",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "hypergrade",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}

func hypergradeDeployment(name string) *appsv1.Deployment {
	one := int32(1)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hypergrade",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app": "hypergrade",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"app": "hypergrade",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"app": "hypergrade",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "hypergrade",
					Containers: []corev1.Container{
						{
							Name: "hypergrade",
							Image: "docker.io/graytshirt/hypergrade:v0.1.0",
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
