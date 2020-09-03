package aws

import (
	"time"
	"encoding/hex"
	"errors"
	"context"
	"math/rand"
	crand "crypto/rand"
	"os/exec"
	log "github.com/sirupsen/logrus"
	"encoding/json"
	"strings"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/wolfeidau/dynalock/v2"
)

type meta struct {
	endpoint    string
	hash        string
	initialized bool
}

var (
	defaultLockTtl   = dynalock.LockWithTTL(8 * time.Minute)
)

func (c Client) Boot() error {

	c.agentStore = dynalock.New(dynamodb.New(c.Cfg), c.ClusterName(), "Agent")
	if c.IsMaster() {
		err := c.StartMaster(0)
		if err != nil {
			log.Error("Failed to start master %v\n", err)
			return err
		}
	} else {
		err := c.StartNode()
		if err != nil {
			log.Error("Failed to start node %v\n", err)
			return err
		}
	}
	return nil
}


func (c Client) StartNode() error {

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
	_, err = runner("sudo kubeadm join --cri-socket unix:///run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight", 3 * time.Minute)
	if err != nil {
		return err
	}
	return nil
}

func (c Client) StartMaster(count int) error {

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
		err := c.JoinMaster()
		if err != nil {
			log.Error("master failed to join control plane %v", err)
			return err
		}
	} else {
		if count >= 35 {
			return errors.New("Timed out requesting lock")
		}
		err := c.StartMaster((count + 1))
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12 * time.Second)
		defer cancel()
		_, err = lock.Lock(ctx, nil)
		defer lock.Unlock(context.Background())
		if err != nil {
			if err == dynalock.ErrLockAcquireCancelled {
				log.Println("ErrLockAcquireCancelled")
			}
			log.Errorf("failed to lock agent: %+v", err)
			return c.StartMaster((count + 1))
		}
		select {
			case <-time.After(20 * time.Millisecond):
				log.Println("finished locking!")
			case <-ctx.Done():
				log.Println(ctx.Err()) // prints "context deadline exceeded"
		}
		if err != nil {
			log.Fatalf("failed to create a new lock on agent: %+v", err)
		}
		err = c.InitMaster()
		if err != nil {
			log.Error("master failed to create control plane %v", err)
			return err
		}
	}

	return nil
}

func (c Client) UploadBootstrapToken(key, token string) error {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return err
	}

	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:           aws.String(c.APITokenLocation),
		SecretString:       aws.String("{\"TOKEN\":\""+token+"\",\"CERTKEY\":\""+key+"\"}"),
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

func (c Client) UploadClusterMeta(m meta) error {
	data, err := json.Marshal(m)
	if err != nil {
		log.Errorf("failed to marshal cluster metadata %v", err)
		return err
	}
	err = c.agentStore.Put(context.Background(), "ClusterMeta", dynalock.WriteWithAttributeValue(&dynamodb.AttributeValue{S: aws.String(string(data))}), dynalock.WriteWithTTL(1 * time.Second))
	if err != nil {
		log.Errorf("failed to upload cluster metadata %v", err)
		return err
	}
	return nil
}

func (c Client) controlPlaneInitialized() (bool, error) {
	ret, err := c.agentStore.Get(context.Background(), "ClusterMeta")
	if err != nil {
		log.Errorf("failed to upload cluster metadata %v", err)
		return false, err
	}
	var m meta
	err = json.Unmarshal([]byte(*(ret.AttributeValue().S)), &m)
	if err != nil {
		log.Errorf("failed to marshal cluster metadata %v", err)
		return false, err
	}
	return m.initialized, nil
}

func (c Client) JoinMaster() error {

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
	// @TODO Kubeadm commands should probably hook into the Go Module
	_, err = runner("sudo kubeadm join --cri-socket /run/crio/crio.sock " + endpoint + ":6443 --token " + token + " --discovery-token-ca-cert-hash " + caHash + " --skip-phases=preflight --control-plane --certificate-key " + certKey + " --ignore-preflight-errors=DirAvailable--var-lib-etcd,DirAvailable--etc-kubernetes-manifests -k ./kustomize", 5 * time.Minute)
	if err != nil {
		return err
	}
	return nil
}


func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := crand.Read(bytes); err != nil {
		log.Errorf("failed to read dev-rand %v", err)
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

/*
 * InitMaster is going to be funky as it needs to setup the cluster for things like CNI, AWS-IRSA, etc
 */
func (c Client) InitMaster() error {
	// key=$(hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random)
	// @TODO Kubeadm commands should probably hook into the Go Module
	key, err := randomHex(16)
	if err != nil {
		return err
	}

	output, err := runner("sudo kubeadm init --cri-socket /run/crio/crio.sock --config kubeadm.conf.yaml --upload-certs -k ./kustomize --skip-phases=preflight,addon/kube-proxy", 8 * time.Minute)
	if err != nil {
		return err
	}
	// @TODO Kubeadm commands should probably hook into the Go Module
	token, err  := runner("sudo kubeadm token create --ttl=0 2>/dev/null", 3 * time.Second)
	if err != nil {
		return err
	}
	err = c.UploadBootstrapToken(key, token)
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
	err = c.UploadClusterMeta(meta{hash: tokenHash, initialized: true})
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
	log.Debug("Running: %s\n", command)

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
