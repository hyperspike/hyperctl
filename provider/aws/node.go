package aws

import (
	"time"
	"github.com/pkg/errors"
	"context"
	"math/rand"
	"os"
	"os/exec"

	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"

	jose "gopkg.in/square/go-jose.v2"

	log "github.com/sirupsen/logrus"
	"github.com/google/uuid"
	"strings"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/wolfeidau/dynalock/v2"
	"hyperspike.io/hyperctl/templates/kubeadm"
	"hyperspike.io/hyperctl/deployer"
	"hyperspike.io/hyperctl"
)

type masterData struct {
	Endpoint      string `json:"apiEndpoint,omitempty"`
	TokenLocation string `json:"tokenLocation,omitempty"`
	CAHash        string `json:"caHash,omitempty"`
	Initialized   bool   `json:"initialized,omitempty"`
	Service       string `json:"service,omitempty"`
	Pods          string `json:"pods,omitempty"`
	KeyARN        string `json:"keyarn,omitempty"`
	Bucket        string `json:"bucket,omitempty"`
}

var (
	defaultLockTtl   = dynalock.LockWithTTL(8 * time.Minute)
)

func (c *Client) Boot() error {

	c.agentStore = dynalock.New(dynamodb.New(c.Cfg), c.ClusterName(), "Agent")
	err := machineID()
	if err != nil {
		return err
	}
	_, err = runner("hostname -f > /etc/hostname", 1 * time.Second)
	if err != nil {
		return err
	}
	_, err = runner("resize2fs /dev/xvda", 2 * time.Second)
	if err != nil {
		return err
	}
	_, err = runner("rc-service hostname restart", 5 * time.Second)
	if err != nil {
		return err
	}
	_, err = runner("rc-update add kubelet default", 2 * time.Second)
	if err != nil {
		return err
	}
	if c.IsMaster() {
		err := c.startMaster(0)
		if err != nil {
			log.Errorf("Failed to start master %v\n", err)
			return err
		}
	} else {
		err := c.startNode()
		if err != nil {
			log.Errorf("Failed to start node %v\n", err)
			return err
		}
	}
	return nil
}


func (c Client) startNode() error {

	endpoint, err := c.GetAPIEndpoint()
	if err != nil {
		log.Error("error fetching endpoint", err)
		return err
	}
	token, err := c.GetAPIToken()
	if err != nil {
		log.Error("error getting token", err)
		return err
	}
	caHash, err := c.GetAPICAHash()
	if err != nil {
		log.Error("error getting CA Hash", err)
		return err
	}
	// @TODO Kubeadm commands should probably hook into the Go Module
	_, err = runner("kubeadm join --cri-socket unix:///run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight", 3 * time.Minute)
	if err != nil {
		return err
	}
	return nil
}

func (c Client) startMaster(count int) error {

	agentName := "master/" + c.InstanceID()
	log.Printf("creating agent: %s", agentName)
	rand.Seed(time.Now().UnixNano())

	lockStore := dynalock.New(dynamodb.New(c.Cfg), c.ClusterName(), "Lock")

	lock, err := lockStore.NewLock(context.Background(), agentName + ".lock", defaultLockTtl)
	if err != nil {
		log.Errorf("failed to create lock %v", err)
		return err
	}

	if init, _ := c.controlPlaneInitialized(); init {
		err := c.joinMaster()
		if err != nil {
			log.Errorf("master failed to join control plane %v", err)
			return err
		}
	} else {
		if count >= 35 {
			return errors.New("Timed out requesting lock")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12 * time.Second)
		defer cancel()
		_, err = lock.Lock(ctx, nil)
		defer unlock(lock)
		if err != nil {
			if err == dynalock.ErrLockAcquireCancelled {
				log.Println("ErrLockAcquireCancelled")
			}
			log.Errorf("failed to lock agent: %+v", err)
			return c.startMaster((count + 1))
		}
		select {
			case <-time.After(20 * time.Millisecond):
				log.Println("finished locking!")
			case <-ctx.Done():
				log.Println(ctx.Err()) // prints "context deadline exceeded"
		}
		if err != nil {
			log.Errorf("failed to create a new lock on agent: %+v", err)
			return c.startMaster((count + 1))
		}
		err = c.initMaster()
		if err != nil {
			log.Errorf("master failed to create control plane %v", err)
			return c.startMaster((count + 1))
		}
	}

	return nil
}

func unlock(lock dynalock.Locker) {
	err := lock.Unlock(context.Background())
	if err != nil {
		log.Errorf("failed to unlock %err", err)
	}
}

func (c Client) UploadBootstrapToken(key, token string) error {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return err
	}

	tokenStrip := strings.Trim(token, "\n")
	tokenStrip = strings.Trim(tokenStrip, "\r")
	keyStrip   := strings.Trim(key, "\n")
	keyStrip   = strings.Trim(keyStrip, "\r")

	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:           aws.String(c.master.TokenLocation),
		SecretString:       aws.String("{\"TOKEN\":\""+tokenStrip+"\",\"CERTKEY\":\""+keyStrip+"\"}"),
	}

	req := svc.PutSecretValueRequest(input)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeLimitExceededException:
				log.Println(secretsmanager.ErrCodeLimitExceededException, aerr.Error())
			case secretsmanager.ErrCodeEncryptionFailure:
				log.Println(secretsmanager.ErrCodeEncryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeResourceExistsException:
				log.Println(secretsmanager.ErrCodeResourceExistsException, aerr.Error())
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return err
	}
	return nil
}

func (c Client) uploadClusterMeta(m masterData, initial bool) error {
	data, err := json.Marshal(m)
	if err != nil {
		log.Errorf("failed to marshal cluster metadata %v", err)
		return err
	}
	err = c.agentStore.Put(context.Background(), "ClusterMeta", dynalock.WriteWithAttributeValue(&dynamodb.AttributeValue{S: aws.String(string(data))}), dynalock.WriteWithTTL(7 * 24 * time.Hour))
	if err != nil {
		log.Errorf("failed to upload cluster metadata %v", err)
		return err
	}
	return nil
}

func (c *Client) controlPlaneMeta() (*masterData, error) {
	ret, err := c.agentStore.Get(context.Background(), "ClusterMeta")
	if err != nil {
		log.Errorf("failed to get cluster metadata %v", err)
		return nil, err
	}
	m := new(masterData)
	err = json.Unmarshal([]byte(*(ret.AttributeValue().S)), m)
	if err != nil {
		log.Errorf("failed to unmarshal cluster metadata %v", err)
		return nil, err
	}
	return m, nil
}

func (c Client) controlPlaneInitialized() (bool, error) {
	m, err := c.controlPlaneMeta()
	if err != nil {
		return false, err
	}
	return m.Initialized, nil
}

func (c Client) joinMaster() error {

	endpoint, err := c.GetAPIEndpoint()
	if err != nil {
		log.Error("error fetching endpoint", err)
		return err
	}
	token, err := c.GetAPIToken()
	if err != nil {
		log.Error("error getting token", err)
		return err
	}
	caHash, err := c.GetAPICAHash()
	if err != nil {
		log.Error("error getting CA Hash", err)
		return err
	}
	certKey, err := c.GetAPICertKey()
	if err != nil {
		log.Error("error getting Certificate Key", err)
		return err
	}
	m, err := c.controlPlaneMeta()
	if err != nil {
		return err
	}

	if _, err := os.Stat("/etc/kubernetes"); os.IsNotExist(err) {
		err = os.Mkdir("/etc/kubernetes", 0755)
		if err != nil {
			return err
		}
	}

	if _, err := os.Stat("/etc/kubernetes/manifests"); os.IsNotExist(err) {
		err = os.Mkdir("/etc/kubernetes/manifests", 0755)
		if err != nil {
			return err
		}
	}

	k := kubeadm.New(c.ClusterName()+"."+c.Region, c.InstanceIP(), c.Region, m.Endpoint, m.Pods, m.Service, m.KeyARN, hyperctl.KubeVersion)
	err = k.SecretsProviderFile("/etc/kubernetes/manifests/api-secrets-provider.yaml")
	if err != nil {
		return err
	}
	err = k.SecretsFile("/etc/kubernetes/secrets.yaml")
	if err != nil {
		return err
	}

	err = os.Mkdir("kustomize", 0755)
	if err != nil {
		return err
	}
	err = k.KustomizationFile("kustomize/kustomization.yaml")
	if err != nil {
		return err
	}
	err = k.ApiSecretsProviderFile("kustomize/api-secrets-provider.yaml")
	if err != nil {
		return err
	}
	// @TODO Kubeadm commands should probably hook into the Go Module
	_, err = runner("kubeadm join --cri-socket /run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight --control-plane --certificate-key " + certKey + " --ignore-preflight-errors=DirAvailable--var-lib-etcd,DirAvailable--etc-kubernetes-manifests -k ./kustomize", 5 * time.Minute)
	if err != nil {
		return err
	}
	return nil
}

func machineID() error {
	id, err := uuid.NewUUID()
	if err != nil {
		log.Errorf("failed to generate machine id %v", err)
		return err
	}
	file, err := os.Create("/etc/machine-id")
	if err != nil {
		log.Errorf("failed to create /etc/machine-id %v", err)
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, strings.ReplaceAll(id.String(), "-", ""))
	if err != nil {
		log.Errorf("failed to write /etc/machine-id, %v", err)
		return err
	}

	return file.Sync()
}

/*
 * InitMaster is going to be funky as it needs to setup the cluster for things like CNI, AWS-IRSA, etc
 */
func (c Client) initMaster() error {
	// key=$(hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random)
	// @TODO Kubeadm commands should probably hook into the Go Module
	m, err := c.controlPlaneMeta()
	if err != nil {
		return err
	}

	if _, err := os.Stat("/etc/kubernetes"); os.IsNotExist(err) {
		err = os.Mkdir("/etc/kubernetes", 0755)
		if err != nil {
			return err
		}
	}

	if _, err := os.Stat("/etc/kubernetes/manifests"); os.IsNotExist(err) {
		err = os.Mkdir("/etc/kubernetes/manifests", 0755)
		if err != nil {
			return err
		}
	}

	k := kubeadm.New(strings.ReplaceAll(c.ClusterName(),"-", "."), c.InstanceIP(), c.InstanceRegion(), m.Endpoint, m.Pods, m.Service, m.KeyARN, hyperctl.KubeVersion)
	err = k.SecretsProviderFile("/etc/kubernetes/manifests/api-secrets-provider.yaml")
	if err != nil {
		return err
	}
	err = k.SecretsFile("/etc/kubernetes/secrets.yaml")
	if err != nil {
		return err
	}

	err = os.Mkdir("kustomize", 0755)
	if err != nil {
		return err
	}
	err = k.KustomizationFile("kustomize/kustomization.yaml")
	if err != nil {
		return err
	}
	err = k.ApiSecretsProviderFile("kustomize/api-secrets-provider.yaml")
	if err != nil {
		return err
	}
	err = k.KubeadmFile("kubeadm.conf.yaml")
	if err != nil {
		return err
	}
	output, err := runner("kubeadm init --cri-socket /run/crio/crio.sock --config kubeadm.conf.yaml --upload-certs -k ./kustomize --skip-phases=preflight,addon/kube-proxy", 8 * time.Minute)
	if err != nil {
		return err
	}
	// @TODO Kubeadm commands should probably hook into the Go Module
	token, err  := runner("kubeadm token create --ttl=0 2>/dev/null", 3 * time.Second)
	if err != nil {
		return err
	}
	err = c.UploadBootstrapToken(k.CertKey, token)
	if err != nil {
		return err
	}
	var tokenHash string
	r := regexp.MustCompile(`--discovery-token-ca-cert-hash`)
	for _, line := range strings.Split(output,"\n") {
		//fmt.Printf("%s: %t\n", line, r.MatchString(line))
		if r.MatchString(line) {
			tokenHash = strings.Trim(string(r.ReplaceAll([]byte(line), []byte("")))," \t\n\r")
		}
	}
	err = c.uploadClusterMeta(masterData{Endpoint: m.Endpoint, TokenLocation: m.TokenLocation, CAHash: tokenHash, Initialized: true, KeyARN: m.KeyARN, Bucket: m.Bucket, Service: m.Service, Pods: m.Pods}, false)
	if err != nil {
		return err
	}
	d, err := deployer.New(m.Endpoint, m.Pods, c.ClusterName())
	if err != nil {
		return err
	}
	err = d.CCM()
	if err != nil {
		return err
	}
	err = d.Cilium()
	if err != nil {
		return err
	}
	_, err = readKey("/etc/kubernetes/pki/sa.pub")
	if err != nil {
		return err
	}

	return nil
}

func runner(command string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // The cancel should be deferred so resources are cleaned up

	// Create the command with our context
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)

	// This time we can simply use Output() to get the result.
	out, err := cmd.Output()
	log.Debugf("Running: %s\n", command)

	// We want to check the context error to see if the timeout was executed.
	// The error returned by cmd.Output() will be OS specific based on what
	// happens when a process is killed.
	if ctx.Err() == context.DeadlineExceeded {
		log.Error("Command timed out")
		return "", ctx.Err()
	} else if err != nil {
	// If there's no context error, we know the command completed (or errored).
		log.Error("Non-zero exit code:", err)
		return "", err
	}
	log.Debug("Output:", string(out))

	return string(out), nil
}

// copied from kubernetes/kubernetes#78502
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Errorf("failed to serialize public key to DER format: %v", err)
		return "", err
	}

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(publicKeyDERBytes)
	if err != nil {
		log.Errorf("failed to hash x509 %v", err)
		return "", nil
	}
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

type keyResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func readKey(filename string) (*keyResponse, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.WithMessage(err, "error reading file")
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.Errorf("Error decoding PEM file %s", filename)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing key content of %s", filename)
	}
	switch pubKey.(type) {
	case *rsa.PublicKey:
	default:
		return nil, errors.New("Public key was not RSA")
	}

	var alg jose.SignatureAlgorithm
	switch pubKey.(type) {
	case *rsa.PublicKey:
		alg = jose.RS256
	default:
		log.Errorf("invalid public key type %T, must be *rsa.PrivateKey", pubKey)
		return nil, errors.New(fmt.Sprintf("invalid public key type %T, must be *rsa.PrivateKey", pubKey))
	}

	kid, err := keyIDFromPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(alg),
		Use:       "sig",
	})

	return &keyResponse{Keys: keys}, nil
}
