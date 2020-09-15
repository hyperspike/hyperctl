package aws

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"encoding/json"
)

type statement struct {
	effect string `json:"Effect"`
	action []string `json:"Action"`
	resource []string `json:"Resource"`
}

type policy struct {
	version string `json:"Version"`
	statement []statement `json:"Statement"`
}

func (p policy) String() string {
	p.version = "2012-10-17"
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c Client) AttachPolicy(role, policyArn string) error {
	svc := iam.New(c.Cfg)
	input := &iam.AttachRolePolicyInput{
		PolicyArn: aws.String(policyArn),
		RoleName:  aws.String(role),
	}
	req := svc.AttachRolePolicyRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		return err
	}
	return nil
}

func (c Client) CreatePolicy(name string, p policy) (string, error) {
	svc := iam.New(c.Cfg)

	input := &iam.CreatePolicyInput{
		Description: aws.String( name + " Policy"),
		Path: aws.String("/"),
		PolicyDocument: aws.String(p.String()),
		PolicyName: aws.String(name),
	}
	resp, err := svc.CreatePolicyRequest(input).Send(context.TODO())
	if err != nil {
		return "", err
	}
	return *resp.Policy.Arn, nil
}

type principal map[string]string

type roleStatement struct {
	action string `json:"Action"`
	principal principal `json:"Principal"`
	effect string `json:"Effect"`
	sid    string `json:"Sid"`
}

type role struct {
	version string `json:"Version"`
	statement []roleStatement `json:"Statement"`
}

func (r role) String() string {
	r.version = "2012-10-17"
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c Client) CreateRole(name string, r role) (string, error) {
	svc := iam.New(c.Cfg)

	input := &iam.CreateRoleInput{
		Description: aws.String(name + " Role"),
		Path: aws.String("/"),
		AssumeRolePolicyDocument: aws.String(r.String()),
		RoleName: aws.String(name),
	}
	resp, err := svc.CreateRoleRequest(input).Send(context.TODO())
	if err != nil {
		return "", err
	}
	return *resp.Role.Arn, nil
}
