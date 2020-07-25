package aws

import (
	"fmt"
	"context"
	"time"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws"
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
	date := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	for _, image := range result.Images {
		t, _ := time.Parse(time.RFC3339, *image.CreationDate)
		if t.Unix() > date.Unix() {
			date = t
			ami = *image.ImageId
		}
	}
	return ami, nil
}
