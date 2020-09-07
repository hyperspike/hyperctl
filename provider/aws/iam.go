package aws

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"encoding/json"
)

type statement struct {
	Effect string
	Action []string
	Resource []string
}

type policy struct {
	Version string
	Statement []statement
}

func (p policy) String() string {
	p.Version = "2012-10-17"
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
