package deployer


import (
	"context"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	admv1  "k8s.io/api/admissionregistration/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"strings"
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
	"math/big"
	"bytes"
)

func (d *Deployer) IRSA() error {
	log.Infof("deploying irsa to %s", d.cluster)
	if err := d.ciliumServiceAccount("pod-identity-webhook") ; err != nil {
		return err
	}
	if err := d.r.Create(context.Background(), irsaClusterRole()); err != nil {
		log.Errorf("failed to create irsa cluster role, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), irsaClusterRoleBinding()); err != nil {
		log.Errorf("failed to create irsa cluster role binding, %v", err)
		return err
	}
	if err := d.r.Create(context.Background(), irsaService()); err != nil {
		log.Errorf("failed to create irsa service, %v", err)
		return err
	}
	cert, key, err := d.generateCerts()
	if err != nil {
		return err
	}
	if err := d.r.Create(context.Background(), createIRSATlsSecret(cert, key)); err != nil {
		log.Errorf("failed to create irsa webhook, %v", err)
		return err
	}
	ca, err := d.getTlsCert()
	if err != nil {
		return err
	}
	if err := d.r.Create(context.Background(), irsaDeployment()); err != nil {
		log.Errorf("failed to create irsa deployment, %v", err)
		return err
	}
	ca = []byte(strings.ReplaceAll(string(ca), "\n", "\\n"))
	if err := d.r.Create(context.Background(), irsaWebhook(ca)); err != nil {
		log.Errorf("failed to create irsa webhook, %v", err)
		return err
	}
	return nil
}

func createIRSATlsSecret(cert, key []byte) *corev1.Secret { // {{{
	return createTlsSecret(cert,key,"pod-identity-webhook","kube-system")
}
// }}}

func createTlsSecret(cert, key []byte, name, namespace string) *corev1.Secret { // {{{
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind: "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Namespace: namespace,
		},
		StringData: map[string]string{
			"tls.crt": string(cert),
			"tls.key": string(key),
		},
		Type: "generic",
	}
}
// }}}

func (d *Deployer) getTlsCert() ([]byte, error) { // {{{
	secret := &corev1.Secret{}
	err := d.r.Get(context.Background(), types.NamespacedName{Name: "pod-identity-webhook", Namespace: "kube-system"}, secret)
	if err != nil {
		log.Errorf("failed to get irsa secret, %v", err)
		return []byte(""), err
	}
	return secret.Data["tls.crt"], nil
}
// }}}

func irsaClusterRole() *rbacv1.ClusterRole { // {{{
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-identity-webhook",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"create",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
				},
			},
			{
				Verbs: []string{
					"get",
					"update",
					"patch",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
				},
				ResourceNames: []string{
					"pod-identity-webhook",
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
					"serviceaccounts",
				},
			},
			{
				Verbs: []string{
					"create",
					"get",
					"list",
					"watch",
				},
				APIGroups: []string{
					"certificates.k8s.io",
				},
				Resources: []string{
					"certificatesigningrequests",
				},
			},
		},
	}
}
// }}}

func irsaClusterRoleBinding() *rbacv1.ClusterRoleBinding { // {{{
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-identity-webhook",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind: "ClusterRole",
			Name: "pod-identity-webhook",
		},
		Subjects: []rbacv1.Subject{
			{
				Name: "pod-identity-webhook",
				Kind: "ServiceAccount",
				Namespace: "kube-system",
			},
		},
	}
}
// }}}

func irsaDeployment() *appsv1.Deployment { // {{{
	one := int32(1)
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind: "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-identity-webhook",
			Namespace: "kube-system",
			Labels: map[string]string {
				"app": "pod-identity-webhook",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &one,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string {
					"app": "pod-identity-webhook",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string {
						"app": "pod-identity-webhook",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "pod-identity-webhook",
					Containers: []corev1.Container{
						{
							Name: "pod-identity-webhook",
							Image: "docker.io/graytshirt/irsa-webhook:0.0.1",
							Command: []string{
								"/webhook",
							},
							Args: []string{
								"--in-cluster",
								"--namespace=kube-system",
								"--service-name=pod-identity-webhook",
								"--tls-secret=pod-identity-webhook",
								"--annotation-prefix=eks.amazonaws.com",
								"--token-audience=sts.amazonaws.com",
								"--logtostderr",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name: "webhook-certs",
									MountPath: "/var/run/app/certs",
									ReadOnly: false,
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
							Name: "webhook-certs",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}
}
// }}}

func irsaService() *corev1.Service { // {{{
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind: "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-identity-webhook",
			Namespace: "kube-system",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port: 443,
					TargetPort: intstr.FromInt(443),
				},
			},
			Selector: map[string]string{
				"app": "pod-identity-webhook",
			},
		},
	}
}
// }}}

func (d *Deployer) generateCerts() ([]byte, []byte, error) { // {{{
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Errorf("failed to generate irsa key, %v", err)
		return []byte(""), []byte(""), err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	keyUsage |= x509.KeyUsageKeyEncipherment

	notBefore := time.Now()
	notAfter  := notBefore.Add(time.Hour * 24 * 375)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Errorf("Failed to generate serial number: %v", err)
		return []byte(""), []byte(""), err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{d.cluster},
			CommonName: "pod-identity-webhook.kube-system.svc",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage: keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			"pod-identity-webhook",
			"pod-identity-webhook.kube-system.svc",
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Errorf("Failed to create certificate: %v", err)
		return []byte(""), []byte(""), err
	}

	var certOut bytes.Buffer
	if err := pem.Encode(&certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Errorf("Failed to write data to cert.pem: %v", err)
		return []byte(""), []byte(""), err
	}


	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Errorf("Unable to marshal private key: %v", err)
		return []byte(""), []byte(""), err
	}

	var keyOut bytes.Buffer
	if err := pem.Encode(&keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Errorf("Failed to write data to key.pem: %v", err)
		return []byte(""), []byte(""), err
	}

	return certOut.Bytes(), keyOut.Bytes(), nil
}
// }}}

func irsaWebhook(ca []byte) *admv1.MutatingWebhookConfiguration { // {{{
	ignore := admv1.Ignore
	slash  := "/"
	return &admv1.MutatingWebhookConfiguration {
		TypeMeta: metav1.TypeMeta{
			Kind: "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-identity-webhook",
			Namespace: "kube-system",
		},
		Webhooks: []admv1.MutatingWebhook{
			{
				Name: "pod-identity-webhook.amazonaws.com",
				FailurePolicy: &ignore,
				ClientConfig: admv1.WebhookClientConfig{
					Service: &admv1.ServiceReference{
						Name: "pod-identity-webhook",
						Namespace: "kube-system",
						Path: &slash,
					},
					CABundle: ca,
				},
				Rules: []admv1.RuleWithOperations{
					{
						Operations: []admv1.OperationType{
							admv1.Create,
						},
						Rule: admv1.Rule{
							APIGroups: []string{
								"",
							},
							APIVersions: []string{
								"v1",
							},
							Resources: []string{
								"pods",
							},
						},
					},
				},
			},
		},
	}
}
// }}}
