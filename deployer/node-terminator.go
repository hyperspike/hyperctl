package deployer

import (
	"context"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Deployer) NodeTerminator(sesUrl string) error {
	log.Infof("deploying aws-node-termination-handler to %s", d.cluster)
	err := d.r.Create(context.Background(), nodeTerminatorServiceAccount("arn:aws:iam::"+d.accountId+":role/node-terminator-"+d.cluster))
	if err != nil {
		log.Errorf("failed to create node-terminator service account, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), nodeTerminatorClusterRole())
	if err != nil {
		log.Errorf("failed to create node-terminator cluster-role, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), nodeTerminatorClusterRoleBinding())
	if err != nil {
		log.Errorf("failed to create node-terminator cluster-role-binding, %v", err)
		return err
	}
	err = d.r.Create(context.Background(), nodeTerminatorDeployment(sesUrl))
	if err != nil {
		log.Errorf("failed to create node-terminator Deployment, %v", err)
		return err
	}


	return nil
}

func nodeTerminatorServiceAccount(iamRole string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind: "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aws-node-termination-handler",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app.kubernetes.io/name": "aws-node-termination-handler",
				"app.kubernetes.io/instance": "aws-node-termination-handler",
				"k8s-app": "aws-node-termination-handler",
			},
			Annotations: map[string]string {
				"eks.amazonaws.com/role-arn": iamRole,
			},
		},
	}
}

func nodeTerminatorClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aws-node-termination-handler",
			Labels: map[string]string {
				"app.kubernetes.io/name": "aws-node-termination-handler",
				"app.kubernetes.io/instance": "aws-node-termination-handler",
				"k8s-app": "aws-node-termination-handler",
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
					"patch",
					"update",
				},
			},
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"pods",
				},
				Verbs: []string{
					"list",
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
					"extensions",
				},
				Resources: []string{
					"daemonsets",
				},
				Verbs: []string{
					"get",
				},
			},
			{
				APIGroups: []string{
					"apps",
				},
				Resources: []string{
					"daemonsets",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}
}

func nodeTerminatorClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aws-node-termination-handler",
			Labels: map[string]string {
				"app.kubernetes.io/name": "aws-node-termination-handler",
				"app.kubernetes.io/instance": "aws-node-termination-handler",
				"k8s-app": "aws-node-termination-handler",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "aws-node-termination-handler",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "aws-node-termination-handler",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}

func nodeTerminatorDeployment(queueUrl string) *appsv1.Deployment {
	one := int32(1)

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "aws-node-termination-handler",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app.kubernetes.io/name": "aws-node-termination-handler",
				"app.kubernetes.io/instance": "aws-node-termination-handler",
				"k8s-app": "aws-node-termination-handler",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"app.kubernetes.io/name": "aws-node-termination-handler",
					"app.kubernetes.io/instance": "aws-node-termination-handler",
					"kubernetes.io/os": "linux",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"app.kubernetes.io/name": "aws-node-termination-handler",
						"app.kubernetes.io/instance": "aws-node-termination-handler",
						"k8s-app": "aws-node-termination-handler",
						"kubernetes.io/os": "linux",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "aws-node-termination-handler",
					Containers: []corev1.Container{
						{
							Name: "aws-node-termination-handler",
							Image: "docker.io/amazon/aws-node-termination-handler:v1.12.0",
							Env: []corev1.EnvVar{
								{
									Name: "NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "spec.nodeName",
										},
									},
								},
								{
									Name: "POD_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "metadata.name",
										},
									},
								},
								{
									Name: "NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "metadata.namespace",
										},
									},
								},
								{
									Name: "SPOT_POD_IP",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath: "status.podIP",
										},
									},
								},
								{
									Name: "DELETE_LOCAL_DATA",
									Value: "",
								},
								{
									Name: "IGNORE_DAEMON_SETS",
									Value: "",
								},
								{
									Name: "POD_TERMINATION_GRACE_PERIOD",
									Value: "15",
								},
								{
									Name: "NODE_TERMINATIZON_GRACE_PERIOD",
									Value: "20",
								},
								{
									Name: "INSTANCE_METADATA_URL",
									Value: "",
								},
								{
									Name: "WEBHOOK_URL",
									Value: "",
								},
								{
									Name: "WEBHOOK_HEADERS",
									Value: "",
								},
								{
									Name: "WEBHOOK_TEMPLATE",
									Value: "",
								},
								{
									Name: "WEBHOOK_PROXY",
									Value: "",
								},
								{
									Name: "DRY_RUN",
									Value: "false",
								},
								{
									Name: "METADATA_TRIES",
									Value: "3",
								},
								{
									Name: "CORDON_ONLY",
									Value: "false",
								},
								{
									Name: "TAINT_NODE",
									Value: "true",
								},
								{
									Name: "JSON_LOGGING",
									Value: "true",
								},
								{
									Name: "LOG_LEVEL",
									Value: "info",
								},
								{
									Name: "ENABLE_PROMETHEUS_SERVER",
									Value: "true",
								},
								{
									Name: "ENABLE_SPOT_INTERRUPTION_DRAINING",
									Value: "true",
								},
								{
									Name: "ENABLE_SCHEDULED_EVENT_DRAINING",
									Value: "true",
								},
								{
									Name: "ENABLE_REBALANCE_MONITORING",
									Value: "true",
								},
								{
									Name: "QUEUE_URL",
									Value: queueUrl,
								},
								{
									Name: "PROMETHEUS_SERVER_PORT",
									Value: "9092",
								},
								{
									Name: "AWS_REGION",
									Value: "",
								},
								{
									Name: "AWS_ENDPOINT",
									Value: "",
								},
								{
									Name: "CHECK_ASG_TAG_BEFORE_DRAINING",
									Value: "true",
								},
								{
									Name: "MANAGED_ASG_TAG",
									Value: "aws-node-termination-handler/managed",
								},
								{
									Name: "WORKERS",
									Value: "10",
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
				},
			},
		},
	}
}
