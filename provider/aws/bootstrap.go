package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	_ "github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)


func (c Client) CreateCluster() {
	vpc := c.vpc("10.20.0.0/16")
	c.subnet(vpc, "10.20.140.0/24", "Master - 0", false)
	c.subnet(vpc, "10.20.141.0/24", "Master - 1", false)
	c.subnet(vpc, "10.20.142.0/24", "Master - 2", false)
	c.subnet(vpc, "10.20.128.0/22", "Nodes - 0", false)
	c.subnet(vpc, "10.20.132.0/22", "Nodes - 1", false)
	c.subnet(vpc, "10.20.136.0/22", "Nodes - 2", false)
	c.subnet(vpc, "10.20.146.0/24", "Ingress - 0", false)
	c.subnet(vpc, "10.20.147.0/24", "Ingress - 1", false)
	c.subnet(vpc, "10.20.148.0/24", "Ingress - 2", false)
	c.subnet(vpc, "10.20.0.0/26", "Edge - 0", true)
	c.subnet(vpc, "10.20.0.64/26", "Edge - 1", true)
}

func (c Client) vpc(cidr string) string {
	svc := ec2.New(c.Cfg)
	input := &ec2.CreateVpcInput{
		CidrBlock: aws.String(cidr),
	}

	req := svc.CreateVpcRequest(input)
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

	fmt.Printf("%v\n", result)

	inputDns := &ec2.ModifyVpcAttributeInput{
		EnableDnsSupport: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
		VpcId: aws.String(*result.Vpc.VpcId),
	}

	reqDns := svc.ModifyVpcAttributeRequest(inputDns)
	resDns, err := reqDns.Send(context.Background())
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

	fmt.Printf("%v\n", resDns)

	inputDns = &ec2.ModifyVpcAttributeInput{
		EnableDnsHostnames: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
		VpcId: aws.String(*result.Vpc.VpcId),
	}

	reqDns = svc.ModifyVpcAttributeRequest(inputDns)
	resDns, err = reqDns.Send(context.Background())
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

	fmt.Printf("%v\n", resDns)

	tagReq := svc.CreateTagsRequest(&ec2.CreateTagsInput{
		Resources: []string{*result.Vpc.VpcId},
		Tags: []ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(c.Id),
			},
		},
	})
	res, err := tagReq.Send(context.Background())
	if err != nil {
		fmt.Printf("Could not create tags for vpc [%s] %v\n", result.Vpc.VpcId, err)
		return ""
	}
	fmt.Printf("%v\n", res)

	return *result.Vpc.VpcId
}

// create subnets
func (c Client) subnet(vpc string, cidr string, name string, public bool) {
	svc := ec2.New(c.Cfg)
	input := &ec2.CreateSubnetInput{
		CidrBlock: aws.String(cidr),
		VpcId:     aws.String(vpc),
	}

	req := svc.CreateSubnetRequest(input)
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
		return
	}
	fmt.Printf("%v\n", result)
	tagReq := svc.CreateTagsRequest(&ec2.CreateTagsInput{
		Resources: []string{*result.Subnet.SubnetId},
		Tags: []ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(strings.Join([]string{name, c.Id}, " ")),
			},
			{
				Key:   aws.String("KubernetesCluster"),
				Value: aws.String(c.Id),
			},
			{
				Key:   aws.String(strings.Join([]string{"kubernetes.io/cluster/", c.Id}, "")),
				Value: aws.String("owned"),
			},
		},
	})
	res, err := tagReq.Send(context.Background())
	if err != nil {
		fmt.Printf("Could not create tags for vpc [%s] %v\n", result.Subnet.SubnetId, err)
		return
	}

	fmt.Printf("%v\n", res)
}

// create NAT

// create Bastion

// IPSec

// Kube Cluster

// Pull KubeConfig

// CAPI - Bootstrap

// Gitifold on mgmt cluster


