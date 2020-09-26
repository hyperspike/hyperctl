package aws

import (
	"fmt"
	"context"
	"time"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
)

type Secret struct {
	Token string `json:"TOKEN"`
	CertKey string `json:"CERTKEY"`
}
func (c Client) SearchAMI(owner string, tags map[string]string) (string, error) {

	var filters []ec2.Filter
	for k, v := range tags {
		filters = append(filters, ec2.Filter{
			Name: aws.String(k),
			Values: []string{
				v,
			},
		})
	}
	input := &ec2.DescribeImagesInput{
		Owners: []string{
			owner,
		},
		Filters: filters,
	}

	req := c.Ec2.DescribeImagesRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			log.Error("Failed to fetch AMI " + aerr.Error())
		} else {
			log.Error("Failed to fetch AMI " + err.Error())
		}
		return "", err
	}

	var ami string
	date := time.Date(2006, time.November, 10, 23, 0, 0, 0, time.UTC)
	for _, image := range result.Images {
		t, _ := time.Parse(time.RFC3339, *image.CreationDate)
		if t.Unix() > date.Unix() {
			date = t
			ami = *image.ImageId
		}
	}
	return ami, nil
}

func (c Client) ClusterName() string {
	if c.Localized {
		return c.Id
	}
	svcMeta := ec2metadata.New(c.Cfg)
	metadata, err := svcMeta.GetInstanceIdentityDocument(context.Background())
	if err == nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Println(metadata.InstanceID)
	// fetch tags for instance ec2:DescribeTags

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			metadata.InstanceID,
		},
	}
	c.Instance = metadata.InstanceID

	req := c.Ec2.DescribeInstancesRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}

	for _, t := range result.Reservations[0].Instances[0].Tags {
		if *t.Key == "KubernetesCluster" {
			c.Id = *t.Value
		}
		if *t.Key == "kubernetes.io/role/master" {
			c.Role = "master"
		}
		if *t.Key == "kubernetes.io/role/node" {
			c.Role = "node"
		}
	}
	c.IP = *result.Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddress
	c.Localized = true
	return c.Id
}

func (c Client) InstanceID() string {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	return c.Instance
}
func (c Client) InstanceIP() string {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	return c.IP
}
func (c Client) IsMaster() bool {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	if c.Role == "master" {
		return true
	}
	return false
}

func (c Client) GetAPIEndpoint() (string, error) {
	if c.master.Endpoint != "" || c.master.TokenLocation != "" || c.master.CAHash != "" {
		return c.master.Endpoint, nil
	}
	masterData, err := c.controlPlaneMeta()
	if err != nil {
		return "", err
	}
	c.master = *masterData
	return c.master.Endpoint, nil
}

func (c Client) GetAPICAHash() (string, error) {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return "", err
	}
	return c.master.CAHash, nil
}

func (c Client) GetAPIToken() (string, error) {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return "", err
	}

	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(c.master.TokenLocation),
		VersionStage: aws.String("AWSCURRENT"),
	}

	req := svc.GetSecretValueRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {

			fmt.Println(err.Error())
		}
		return "", err
	}

	var secret Secret
	json.Unmarshal([]byte(*result.SecretString), &secret)
	c.APIToken = secret.Token
	c.APICertKey = secret.CertKey

	return c.APIToken, nil
}

func (c Client) GetAPICertKey() (string, error) {
	if c.APICertKey == "" {
		_, err := c.GetAPIToken()
		if err != nil {
			return "", err
		}
	}

	return c.APICertKey, nil
}
