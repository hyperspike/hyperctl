package aws

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"encoding/json"
)

type statement struct {
	Effect string `json:"Effect"`
	Action []string `json:"Action"`
	Resource []string `json:"Resource"`
}

type policy struct {
	Version string `json:"Version"`
	Statement []statement `json:"Statement"`
}

func (p policy) String() string {
	p.Version = "2012-10-17"
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *Client) AttachPolicy(role, policyArn string) error {
	svc := iam.New(c.Cfg)
	input := &iam.AttachRolePolicyInput{
		PolicyArn: aws.String(policyArn),
		RoleName:  aws.String(role),
	}
	req := svc.AttachRolePolicyRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		log.Errorf("Failed to attach role [%s] to policy [%s] [%v]", role, policyArn, err)
		return err
	}
	return nil
}

func (c *Client) CreatePolicy(name string, p policy) (string, error) {
	svc := iam.New(c.Cfg)

	input := &iam.CreatePolicyInput{
		Description: aws.String( name + " Policy"),
		Path: aws.String("/"),
		PolicyDocument: aws.String(p.String()),
		PolicyName: aws.String(name),
	}
	resp, err := svc.CreatePolicyRequest(input).Send(context.TODO())
	if err != nil {
		log.Errorf("Failed to create policy [%s] [%v]", name, err)
		return "", err
	}
	return *resp.Policy.Arn, nil
}

type principal map[string]string

type roleStatement struct {
	Action string `json:"Action"`
	Principal principal `json:"Principal"`
	Effect string `json:"Effect"`
	Sid    string `json:"Sid"`
}

type role struct {
	Version string `json:"Version"`
	Statement []roleStatement `json:"Statement"`
}

func (r role) String() string {
	r.Version = "2012-10-17"
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *Client) CreateRole(name string, r role) (string, error) {
	svc := iam.New(c.Cfg)

	input := &iam.CreateRoleInput{
		Description: aws.String(name + " Role"),
		Path: aws.String("/"),
		AssumeRolePolicyDocument: aws.String(r.String()),
		RoleName: aws.String(name),
	}
	resp, err := svc.CreateRoleRequest(input).Send(context.TODO())
	if err != nil {
		log.Errorf("Failed to create role [%s] [%v]", name, err)
		return "", err
	}
	return *resp.Role.Arn, nil
}
