package aws

import (
	//"context"
	//"github.com/aws/aws-sdk-go-v2/aws"
	// "github.com/aws/aws-sdk-go-v2/aws/awserr"
	// "github.com/aws/aws-sdk-go-v2/service/iam"
	// "github.com/aws/aws-sdk-go-v2/service/s3"
)

func (c Client) IRSAPolicy(bucketArn string) (string, error) {
	p := policy{
		statement: []statement{
			{
				effect: "Allow",
				action: []string{
					"s3:ListBucket",
				},
				resource: []string{
					bucketArn,
				},
			},
			{
				effect: "Allow",
				action: []string{
					"s3:GetObjectVersion",
					"s3:PutObject",
					"s3:PutObjectAcl",
					"s3:GetObject",
				},
				resource: []string{
					bucketArn + "/*",
				},
			},
		},
	}
	arn, err := c.CreatePolicy("irsa-upload-" + c.ClusterName(), p)
	if err != nil {
		return "", err
	}
	return arn, nil
}