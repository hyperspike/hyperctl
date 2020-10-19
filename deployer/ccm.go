package deployer

import (
	"context"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Deployer) CCM() error {
	log.Infof("deploying cloud-contoller-manager to %s", d.cluster)
	err := d.r.Create(context.TODO(), ccmServiceAccount())
	if err != nil {
		log.Errorf("failed to create cloud-controller service account, %v", err)
		return err
	}
	err = d.r.Create(context.TODO(), ccmRoleBinding())
	if err != nil {
		log.Errorf("failed to create elevated priviledges for cloud-controller service account, %v", err)
		return err
	}
	err = d.r.Create(context.TODO(), ccmDeployment(d.endpoint, d.pods, d.cluster))
	if err != nil {
		log.Errorf("failed to create cloud-controller DaemonSet, %v", err)
		return err
	}

	return nil
}

func ccmServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind: "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cloud-controller-manager",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app.kubernetes.io/name": "cloud-controller-manager",
			},
		},

	}
}

func ccmRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "system:cloud-controller-manager",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "ServiceAccount",
				Name: "cloud-controller-manager",
				Namespace: "kube-system",
			},
		},
	}
}

func ccmDeployment(endpoint, pods, cluster string) *appsv1.DaemonSet {

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			Kind: "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cloud-controller-manager",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app.kubernetes.io/name": "cloud-controller-manager",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"app.kubernetes.io/name": "cloud-controller-manager",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"app.kubernetes.io/name": "cloud-controller-manager",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "cloud-controller-manager",
					HostNetwork: true,
					Containers: []corev1.Container{
						{
							Name: "cloud-controller-manager",
							Image: "docker.io/graytshirt/cloud-provider-aws:0.18.0",
							Command: []string{
								"/usr/bin/aws-cloud-controller-manager",
							},
							Args: []string{
								"--leader-elect=true",
								"--use-service-account-credentials",
								"--allocate-node-cidrs=false",
								"--configure-cloud-routes=false",
								"--cluster-cidr="+pods,
								"--cluster-name="+cluster,
								"--secure-port=10224",
							},
							Env: []corev1.EnvVar{
								{
									Name: "KUBERNETES_PORT_6443_TCP",
									Value: "tcp://"+endpoint+":6443",
								},
								{
									Name: "KUBERNETES_SERVICE_PORT",
									Value: "6443",
								},
								{
									Name: "KUBERNETES_PORT",
									Value: "tcp://"+endpoint+":6443",
								},
								{
									Name: "KUBERNETES_SERVICE_HOST",
									Value: endpoint,
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
}
