package aws

import (
	"context"
	"fmt"
	"time"
	"strconv"
	"strings"
	"crypto/sha1"
	"encoding/hex"

	"github.com/aws/aws-sdk-go-v2/aws"
	_ "github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type Client struct {
	Cfg aws.Config
	Tags map[string]string
	Id string
	Ec2 *ec2.Client
}

func Init() Client {
	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	var err error
	var c Client
	c.Cfg, err = external.LoadDefaultAWSConfig()
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}

	h := sha1.New()
	h.Write([]byte(strconv.FormatInt(time.Now().Unix(),10)))
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	// Set the AWS Region that the service clients should use
	c.Id =  strings.Join([]string{"hyperspike", sha1_hash[0:7]},"-")
	c.Cfg.Region = "us-east-2"
	c.Ec2 = ec2.New(c.Cfg)

	// Using the Config value, create the DynamoDB client
	svc := iam.New(c.Cfg)

	req := svc.ListGroupsRequest(nil)

	// Send the request, and get the response or error back
	resp, err := req.Send(context.Background())
	if err != nil {
		panic("failed to describe table, "+err.Error())
	}

	fmt.Println("Response", resp)

	return c
}
