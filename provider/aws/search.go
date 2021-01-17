package aws

import (
	"context"
	"time"
	"math"
	"strconv"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/wolfeidau/dynalock/v2"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type Secret struct {
	Token string `json:"TOKEN"`
	CertKey string `json:"CERTKEY"`
}
func (c *Client) SearchAMI(owner string, tags map[string]string) (string, string,string,error) {

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
		return "", "", "", err
	}

	var img ec2.Image
	date := time.Date(2006, time.November, 10, 23, 0, 0, 0, time.UTC)
	for _, image := range result.Images {
		t, _ := time.Parse(time.RFC3339, *image.CreationDate)
		if t.Unix() > date.Unix() {
			date = t
			img = image
		}
	}
	return *img.ImageId, *img.Name, *img.Description, nil
}

func (c *Client) ClusterName() string {
	if c.Localized {
		return c.Id
	}
	svcMeta := ec2metadata.New(c.Cfg)
	metadata, err := svcMeta.GetInstanceIdentityDocument(context.Background())
	if err != nil {
		log.Errorf("Failed to get instance metadata [%v]", err)
		return ""
	}
	log.Info(metadata.InstanceID)
	// fetch tags for instance ec2:DescribeTags

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{
			metadata.InstanceID,
		},
	}
	c.Instance = metadata.InstanceID
	c.Region   = metadata.Region
	if c.AccountID == "" {
		c.AccountID = metadata.AccountID
	}

	req := c.Ec2.DescribeInstancesRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
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

func (c *Client) InstanceID() string {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	return c.Instance
}
func (c *Client) InstanceRegion() string {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	return c.Region
}
func (c *Client) InstanceIP() string {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	return c.IP
}
func (c *Client) IsMaster() bool {
	if ! c.Localized {
		_ = c.ClusterName()
	}
	if c.Role == "master" {
		return true
	}
	return false
}

func (c *Client) GetAPIEndpoint() (string, error) {
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

func (c *Client) GetAPICAHash() (string, error) {
	if _, err := c.GetAPIEndpoint() ; err != nil {
		return "", err
	}
	return c.master.CAHash, nil
}

func (c *Client) GetAPIToken() (string, error) {
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
				log.Error(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Error(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Error(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeDecryptionFailure:
				log.Error(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Error(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			log.Error(err.Error())
		}
		return "", err
	}

	var secret Secret
	err = json.Unmarshal([]byte(*result.SecretString), &secret)
	if err != nil {
		log.Errorf("failed to unmarshall secretString [%s] %v", c.master.TokenLocation, err)
		return "", err
	}
	c.APIToken = secret.Token
	c.APICertKey = secret.CertKey

	return c.APIToken, nil
}

func (c *Client) GetAPICertKey() (string, error) {
	if c.APICertKey == "" {
		_, err := c.GetAPIToken()
		if err != nil {
			return "", err
		}
	}

	return c.APICertKey, nil
}

type Cluster struct {
	Id string
	Start  int64
	Health string
}

func (c Cluster) Name() string {
	return c.Id
}

func plural(count int, singular string) (result string) {
	if (count == 1) || (count == 0) {
		result = strconv.Itoa(count) + " " + singular + " "
	} else {
		result = strconv.Itoa(count) + " " + singular + "s "
	}
	return
}

func secondsToHuman(input int64) (result string) {
	years := math.Floor(float64(input) / 60 / 60 / 24 / 7 / 30 / 12)
	seconds := input % (60 * 60 * 24 * 7 * 30 * 12)
	months := math.Floor(float64(seconds) / 60 / 60 / 24 / 7 / 30)
	seconds = input % (60 * 60 * 24 * 7 * 30)
	weeks := math.Floor(float64(seconds) / 60 / 60 / 24 / 7)
	seconds = input % (60 * 60 * 24 * 7)
	days := math.Floor(float64(seconds) / 60 / 60 / 24)
	seconds = input % (60 * 60 * 24)
	hours := math.Floor(float64(seconds) / 60 / 60)
	seconds = input % (60 * 60)
	minutes := math.Floor(float64(seconds) / 60)
	seconds = input % 60

	if years > 0 {
		result = plural(int(years), "year") + plural(int(months), "month") + plural(int(weeks), "week") + plural(int(days), "day") + plural(int(hours), "hour") + plural(int(minutes), "minute") + plural(int(seconds), "second")
	} else if months > 0 {
		result = plural(int(months), "month") + plural(int(weeks), "week") + plural(int(days), "day") + plural(int(hours), "hour") + plural(int(minutes), "minute") + plural(int(seconds), "second")
	} else if weeks > 0 {
		result = plural(int(weeks), "week") + plural(int(days), "day") + plural(int(hours), "hour") + plural(int(minutes), "minute") + plural(int(seconds), "second")
	} else if days > 0 {
		result = plural(int(days), "day") + plural(int(hours), "hour") + plural(int(minutes), "minute") + plural(int(seconds), "second")
	} else if hours > 0 {
		result = plural(int(hours), "hour") + plural(int(minutes), "minute") + plural(int(seconds), "second")
	} else if minutes > 0 {
		result = plural(int(minutes), "minute") + plural(int(seconds), "second")
	} else {
		result = plural(int(seconds), "second")
	}

	return
}


func (c Cluster) Age() string {
	now := time.Now().Unix()
	return  secondsToHuman( now - c.Start )
}

func (c Cluster) State() string {
	return c.Health
}

func (c *Client) List() ([]Cluster, error) {
	globalStore := dynalock.New(dynamodb.New(c.Cfg), "hyperspike", "Agent")
	kv, err := globalStore.List(context.Background(), "hyperspike-")
	if err != nil {
		log.Errorf("failed to list clusters, %v", err)
		return []Cluster{}, err
	}
	clusters := []Cluster{}
	for _, k := range kv {
		state := k.AttributeValue().S
		dyn := dynalock.New(dynamodb.New(c.Cfg), k.Key, "Agent")
		ret, err := dyn.Get(context.Background(), "start")
		if err != nil {
			log.Errorf("unable to fetch start for cluster %s, %v", k.Key, err)
			continue
		}
		s := ret.AttributeValue().S
		n, err := strconv.ParseInt(*s, 10, 64)
		if err != nil {
			log.Errorf("unable to parse start for cluster %s, %v", k.Key, err)
			continue
		}
		clusters = append(clusters, Cluster{Id: k.Key, Start: n, Health: *state})
	}
	return clusters, nil
}
