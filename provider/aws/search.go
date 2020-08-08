package aws

import (
	"fmt"
	"context"
	"time"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"encoding/json"
)

type Secret struct {
	Token string `json:"TOKEN"`
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
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {

			fmt.Println(err.Error())
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
	c.Localized = true
	return c.Id
}

func (c Client) GetAPIEndpoint() (string, error) {
	if c.APIEndpoint != "" && c.APITokenLocation != "" && c.APICAHash != "" {
		return c.APIEndpoint, nil
	}
	svc := dynamodb.New(c.Cfg)
	input := &dynamodb.GetItemInput{
		Key: map[string]dynamodb.AttributeValue{
			"Role": {
				S: aws.String("Node"),
			},
		},
		TableName: aws.String(c.ClusterName()),
	}
	req := svc.GetItemRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeProvisionedThroughputExceededException:
				fmt.Println(dynamodb.ErrCodeProvisionedThroughputExceededException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				fmt.Println(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
			case dynamodb.ErrCodeRequestLimitExceeded:
				fmt.Println(dynamodb.ErrCodeRequestLimitExceeded, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				fmt.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return "", err
	}
	c.APIEndpoint      = *result.Item["APIEndpoint"].S
	c.APITokenLocation = *result.Item["APITokenLocation"].S
	c.APICAHash        = *result.Item["APICAHash"].S
	return c.APIEndpoint, nil
}

func (c Client) GetAPICAHash() (string, error) {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return "", err
	}
	return c.APICAHash, nil
}

func (c Client) GetAPIToken() (string, error) {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return "", err
	}

	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(c.APITokenLocation),
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

	return c.APIToken, nil
}
