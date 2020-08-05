package aws

import (
	"fmt"
	"context"
	"time"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
)

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

func (c Client) GetAPIEndpoint() error {
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
		return err
	}
	c.APIEndpoint = *result.Item["APIEndpoint"].S
	return nil
}

func (c Client) GetAPIToken() error {
	// transact to get dynamodb c.Id / node / secretname

	// fetch secretvalue from secretname

	return nil
}
