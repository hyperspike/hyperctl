package aws

import (
	"io"
	"time"
	"strconv"
	"strings"
	// #nosec
	"crypto/sha1"
	"encoding/hex"
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	_ "github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/wolfeidau/dynalock/v2"
)

type Client struct {
	Cfg aws.Config
	state map[string][]string
	syncState *sync.RWMutex
	Tags map[string]string
	Id string
	Ec2 *ec2.Client
	Localized bool
	APIToken   string
	APICertKey string
	master     masterData
	Role       string
	Region     string
	CIDR       string
	Instance   string
	IP         string
	AccountID  string
	agentStore dynalock.Store
}

func Init(region, cidr, service string) *Client {
	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	var err error
	var c Client
	c.state = make(map[string][]string)
	c.Cfg, err = external.LoadDefaultAWSConfig()
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}
	c.Localized = false
	c.syncState = &sync.RWMutex{}
	// #nosec
	h := sha1.New()
	_, err = io.WriteString(h, strconv.FormatInt(time.Now().Unix(),10))
	if err != nil {
		panic("failed to seed sha1 with epoch " + err.Error())
	}
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	// Set the AWS Region that the service clients should use
	c.Id =  strings.Join([]string{"hyperspike", sha1_hash[0:7]},"-")
	if region != "" {
		c.Cfg.Region = region
		c.Region = region
	} else {
		c.Region = c.Cfg.Region
	}
	c.accountId()
	c.CIDR = cidr
	c.master.Service = service
	c.Ec2 = ec2.New(c.Cfg)

	return &c
}

func (c *Client) accountId() {
	svc := sts.New(c.Cfg)
	input := &sts.GetCallerIdentityInput{}

	req := svc.GetCallerIdentityRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Error("failed to get Account ID: "+aerr.Error())
			}
		} else {
			log.Error("failed to get Account ID: "+err.Error())
		}
		return
	}
	// log.Error(result)
	c.AccountID = *result.Account
}
