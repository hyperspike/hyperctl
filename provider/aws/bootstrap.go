package aws

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/sha1"
	"encoding/hex"

	"context"
	"net"
	"strings"
	"time"
	"encoding/base64"
	log "github.com/sirupsen/logrus"

	"hyperspike.io/hyperctl/auth/ssh"
	"hyperspike.io/hyperctl/bootstrap/bastion"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	_ "github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/wolfeidau/dynalock/v2"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)


type Direction string
const (
	Ingress Direction = "ingress"
	Egress  Direction = "egress"
)

type Instance struct {
	name    string
	nat     bool
	ami     string
	subnet  string
	sg      string
	root    int64
	key     string
	size    string
	id      string
	public  string
	private string
}

func (c Client) CreateCluster() {
	_, vpcCidr, err := net.ParseCIDR(c.CIDR)
	if err != nil {
		log.Println(err)
		return
	}

	vpc := c.vpc(vpcCidr.String())
	podCidr, err := cidr.Subnet(vpcCidr, 4, 8)
	if err != nil {
		log.Println(err)
		return
	}
	c.master.Pods = podCidr.String()
	masterACidr, err := cidr.Subnet(vpcCidr, 8, 140)
	if err != nil {
		log.Println(err)
		return
	}
	masterBCidr, err := cidr.Subnet(vpcCidr, 8, 141)
	if err != nil {
		log.Println(err)
		return
	}
	masterCCidr, err := cidr.Subnet(vpcCidr, 8, 142)
	if err != nil {
		log.Println(err)
		return
	}
	nodeACidr, err := cidr.Subnet(vpcCidr, 6, 32)
	if err != nil {
		log.Println(err)
		return
	}
	nodeBCidr, err := cidr.Subnet(vpcCidr, 6, 33)
	if err != nil {
		log.Println(err)
		return
	}
	nodeCCidr, err := cidr.Subnet(vpcCidr, 6, 34)
	if err != nil {
		log.Println(err)
		return
	}
	edgeACidr, err := cidr.Subnet(vpcCidr, 10, 0)
	if err != nil {
		log.Println(err)
		return
	}
	edgeBCidr, err := cidr.Subnet(vpcCidr, 10, 1)
	if err != nil {
		log.Println(err)
		return
	}
	edgeCCidr, err := cidr.Subnet(vpcCidr, 10, 2)
	if err != nil {
		log.Println(err)
		return
	}

	// @TODO get AZs by region search
	masterA := c.subnet(vpc, masterACidr.String(), "Master - 0", false, "use2-az1")
	masterB := c.subnet(vpc, masterBCidr.String(), "Master - 1", false, "use2-az2")
	masterC := c.subnet(vpc, masterCCidr.String(), "Master - 2", false, "use2-az3")
	nodeA   := c.subnet(vpc, nodeACidr.String(), "Nodes - 0", false, "use2-az1")
	nodeB   := c.subnet(vpc, nodeBCidr.String(), "Nodes - 1", false, "use2-az2")
	nodeC   := c.subnet(vpc, nodeCCidr.String(), "Nodes - 2", false, "use2-az3")
	edgeA   := c.subnet(vpc, edgeACidr.String(), "Edge - 0", true, "use2-az1")
	edgeB   := c.subnet(vpc, edgeBCidr.String(), "Edge - 1", true, "use2-az2")
	edgeC   := c.subnet(vpc, edgeCCidr.String(), "Edge - 2", true, "use2-az3")

	gw  := c.gateway(vpc)

	gwRoute  := c.routeTable(vpc, gw,  "0.0.0.0/0")
	c.assocRoute(edgeA, gwRoute)
	c.assocRoute(edgeB, gwRoute)
	c.assocRoute(edgeC, gwRoute)

	edgeSg := c.securityGroup(vpc, "edge", "Edge Bastion")
	masterSg := c.securityGroup(vpc, "master", "Master Nodes")
	masterLbSg := c.securityGroup(vpc, "master-lb", "Master Load Balancer")
	nodeSg := c.securityGroup(vpc, "node", "Worker Nodes")

	edgeEgress := c.securityGroupRule(0, 0, "0.0.0.0/0", "-1", "egress")
	edgeIngress := []ec2.IpPermission{}
	edgeIngress = append(edgeIngress, c.securityGroupRule(22, 22, "0.0.0.0/0", "tcp", "ssh provisioning"))
	edgeIngress = append(edgeIngress, c.securityGroupRule(22223, 22223, "0.0.0.0/0", "tcp", "ssh pivot"))
	edgeIngress = append(edgeIngress, c.securityGroupRule(500, 500, "0.0.0.0/0", "udp", "500 IpSec"))
	edgeIngress = append(edgeIngress, c.securityGroupRule(4500, 4500, "0.0.0.0/0", "udp", "4500 IpSec"))
	edgeIngress = append(edgeIngress, c.securityGroupRule(443, 443, "0.0.0.0/0", "tcp", "https just in case"))
	edgeIngress = append(edgeIngress, c.securityGroupRule(0, 65535, masterSg, "-1", "NAT Master security group"))
	edgeIngress = append(edgeIngress, c.securityGroupRule(0, 65535, nodeSg, "-1", "NAT Node security group"))
	c.securityGroupRuleApply(edgeSg, []ec2.IpPermission{edgeEgress}, Egress)

	c.securityGroupRuleApply(edgeSg, edgeIngress, Ingress)
	c.securityGroupRuleApply(masterSg, []ec2.IpPermission{edgeEgress}, Egress)
	c.securityGroupRuleApply(masterLbSg, []ec2.IpPermission{edgeEgress}, Egress)
	c.securityGroupRuleApply(nodeSg, []ec2.IpPermission{edgeEgress}, Egress)

	masterIngress := []ec2.IpPermission{}
	masterIngress = append(masterIngress, c.securityGroupRule(6443, 6443, podCidr.String(), "tcp", "Allow pods to get API info"))
	masterIngress = append(masterIngress, c.securityGroupRule(443, 443, podCidr.String(), "tcp", "Allow pods to get API info"))
	masterIngress = append(masterIngress, c.securityGroupRule(53, 53, podCidr.String(), "udp", "Allow pods to get DNS"))
	masterIngress = append(masterIngress, c.securityGroupRule(22, 22, edgeSg, "tcp", "ssh provisioning"))
	masterIngress = append(masterIngress, c.securityGroupRule(443, 443, nodeSg, "tcp", "Allow nodes to API"))
	masterIngress = append(masterIngress, c.securityGroupRule(0, 65535, masterSg, "-1", "master master communication"))
	masterIngress = append(masterIngress, c.securityGroupRule(6443, 6443, masterLbSg, "tcp", "master-lb master communication"))
	c.securityGroupRuleApply(masterSg, masterIngress, Ingress)
	masterLbIngress := []ec2.IpPermission{}
	masterLbIngress = append(masterLbIngress, c.securityGroupRule(6443, 6443, edgeSg, "tcp", "VPN Users to get kubectl"))
	masterLbIngress = append(masterLbIngress, c.securityGroupRule(6443, 6443, nodeSg, "tcp", "Nodes to API"))
	masterLbIngress = append(masterLbIngress, c.securityGroupRule(6443, 6443, masterSg, "tcp", "Nodes to API"))
	c.securityGroupRuleApply(masterLbSg, masterLbIngress, Ingress)
	nodeIngress := []ec2.IpPermission{}
	nodeIngress = append(nodeIngress, c.securityGroupRule(10250, 10250, masterSg, "tcp", "master to kubelet"))
	nodeIngress = append(nodeIngress, c.securityGroupRule(1024, 65535, masterSg, "tcp", "Pod Comunication"))
	nodeIngress = append(nodeIngress, c.securityGroupRule(0, 65535, nodeSg, "-1", "node to node"))
	nodeIngress = append(nodeIngress, c.securityGroupRule(22, 22, edgeSg, "tcp", "edge ssh"))
	c.securityGroupRuleApply(nodeSg, nodeIngress, Ingress)

	key := ssh.New(4096)
	err = key.WritePrivateKey("bastion-"+c.Id)
	if err != nil {
		return
	}
	bastionKey := c.key(c.Id, key)
	/* @TODO fix hardcoded AMI
	 * Move to Edge Nodes with Cilium XDP Load Balancing
	 */
	fwA, _ := c.instance(&Instance{name:"Firewall - 1", ami:"ami-008a61f78ba92b950", key:bastionKey, subnet:edgeA, sg:edgeSg, nat: true})

	natRoute := c.routeTable(vpc, fwA.id, "0.0.0.0/0")
	c.assocRoute(masterA, natRoute)
	c.assocRoute(masterB, natRoute)
	c.assocRoute(masterC, natRoute)
	c.assocRoute(nodeA, natRoute)
	c.assocRoute(nodeB, natRoute)
	c.assocRoute(nodeC, natRoute)
	fwHostA := bastion.New(fwA.public + "/32" , 22, key.PrivateKey, "alpine")
	err = fwHostA.Run([]string{
		"sudo su -c 'echo http://dl-cdn.alpinelinux.org/alpine/edge/main/ >> /etc/apk/repositories'",
		"sudo su -c 'echo http://dl-cdn.alpinelinux.org/alpine/edge/community/ >> /etc/apk/repositories'",
		"sudo apk update",
		//"sudo apk add -u openssh iptables suricata",
		"sudo apk add -u openssh iptables",
		`sudo  sed -i -e 's/^\(AllowTcpForwarding\)\s\+\w\+/\1 yes/' /etc/ssh/sshd_config`,
		"sudo rc-service sshd restart",
		//"sudo rc-update add suricata default",
		//"sudo rc-service suricata start",
		"sudo su -c 'echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf'",
		"sudo sysctl -p",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s " + masterACidr.String() + " -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s " + masterBCidr.String() + " -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s " + masterCCidr.String() + " -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s " + nodeACidr.String() + " -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s " + nodeBCidr.String() + " -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s " + nodeCCidr.String() + " -j MASQUERADE",
		//"sudo iptables -I INPUT -j NFQUEUE",
		//"sudo iptables -I OUTPUT -j NFQUEUE",
		//"sudo iptables -t nat -I INPUT -j NFQUEUE",
		//"sudo iptables -t nat -I OUTPUT -j NFQUEUE",
		"sudo rc-service iptables save",
	})
	if err != nil {
		return
	}

	r := role{
		Statement: []roleStatement{
			{
				Action: "sts:AssumeRole",
				Effect: "Allow",
				// Sid:    "",
				Principal: principal{
					"Service": "ec2.amazonaws.com",
				},
			},
		},
	}
	_, err = c.CreateRole("master-"+c.Id, r)
	if err != nil {
		return
	}
	_, err = c.CreateRole("node-"+c.Id, r)
	if err != nil {
		return
	}
	mGP := policy{
		Statement: []statement{
			{
				Action: []string{
					"ec2:DescribeInstances",
					"ec2:DescribeRegions",
					"ec2:DescribeRouteTables",
					"ec2:DescribeSecurityGroups",
					"ec2:DescribeSubnets",
					"ec2:DescribeVolumes",
					"ec2:CreateSecurityGroup",
					"ec2:CreateTags",
					"ec2:CreateVolume",
					"ec2:ModifyInstanceAttribute",
					"ec2:ModifyVolume",
					"ec2:AttachVolume",
					"ec2:AuthorizeSecurityGroupIngress",
					"ec2:CreateRoute",
					"ec2:DeleteRoute",
					"ec2:DeleteSecurityGroup",
					"ec2:DeleteVolume",
					"ec2:DetachVolume",
					"ec2:RevokeSecurityGroupIngress",
					"ec2:DescribeVpcs",
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:AttachLoadBalancerToSubnets",
					"elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
					"elasticloadbalancing:CreateLoadBalancer",
					"elasticloadbalancing:CreateLoadBalancerPolicy",
					"elasticloadbalancing:CreateLoadBalancerListeners",
					"elasticloadbalancing:ConfigureHealthCheck",
					"elasticloadbalancing:DeleteLoadBalancer",
					"elasticloadbalancing:DeleteLoadBalancerListeners",
					"elasticloadbalancing:DescribeLoadBalancers",
					"elasticloadbalancing:DescribeLoadBalancerAttributes",
					"elasticloadbalancing:DetachLoadBalancerFromSubnets",
					"elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
					"elasticloadbalancing:ModifyLoadBalancerAttributes",
					"elasticloadbalancing:RegisterInstancesWithLoadBalancer",
					"elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer",
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:CreateListener",
					"elasticloadbalancing:CreateTargetGroup",
					"elasticloadbalancing:DeleteListener",
					"elasticloadbalancing:DeleteTargetGroup",
					"elasticloadbalancing:DescribeListeners",
					"elasticloadbalancing:DescribeLoadBalancerPolicies",
					"elasticloadbalancing:DescribeTargetGroups",
					"elasticloadbalancing:DescribeTargetHealth",
					"elasticloadbalancing:ModifyListener",
					"elasticloadbalancing:ModifyTargetGroup",
					"elasticloadbalancing:RegisterTargets",
					"elasticloadbalancing:SetLoadBalancerPoliciesOfListener",
				},
				Resource: []string{
					"*",
				},
				Effect: "Allow",
			},
		},
	}
	masterPolicy, err := c.CreatePolicy("master-general-"+c.Id, mGP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, masterPolicy)
	if err != nil {
		return
	}
	nGP := policy{
		Statement: []statement{
			{
				Action: []string{
					"ec2:DescribeInstances",
					"ec2:DescribeRegions",
				},
				Resource: []string{
					"*",
				},
				Effect: "Allow",
			},
		},
	}
	nodePolicy, err := c.CreatePolicy("node-general-"+c.Id, nGP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("node-"+c.Id, nodePolicy)
	if err != nil {
		return
	}

	masterProfile, err := c.instanceProfile("master-"+c.Id)
	if err != nil {
		return
	}
	nodeProfile, err := c.instanceProfile("node-"+c.Id)
	if err != nil {
		return
	}
	err = c.addRoleInstance("master-"+c.Id, "master-"+c.Id)
	if err != nil {
		return
	}
	err = c.addRoleInstance("node-"+c.Id, "node-"+c.Id)
	if err != nil {
		return
	}


	ami, err := c.SearchAMI("751883444564", map[string]string{"name":"hyperspike-*"})
	if err != nil {
		return
	}
	log.Info("creating launch templates")
	_, err = c.createLaunchTemplate("master-"+c.Id, "t3a.medium", ami, masterProfile, bastionKey, masterSg, `#!/bin/sh
sudo hyperctl boot`)
	if err != nil {
		return
	}
	_, err = c.createLaunchTemplate("node-"+c.Id, "t3a.medium", ami, nodeProfile, bastionKey, nodeSg, `#!/bin/sh
sudo hyperctl boot`)
	if err != nil {
		return
	}

	log.Info("creating master load balancer")
	c.master.Endpoint, err = c.loadBalancer("master-lb-"+c.Id, masterLbSg, []string{masterA, masterB, masterC})
	if err != nil {
		return
	}
	log.Info("creating IRSA OIDC s3 bucket")
	irsaBucket, err := c.bucket(c.Id+"-irsa")
	c.master.Bucket = irsaBucket
	if err != nil {
		return
	}
	_, err = c.oidcIAM("https://s3."+c.Region+".amazonaws.com/"+c.Id+"-irsa/")
	if err != nil {
		return
	}
	irsaPolicy, err := c.IRSAPolicy(irsaBucket)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, irsaPolicy)
	if err != nil {
		return
	}
	var kmsKey string
	kmsKey, c.master.KeyARN, err = c.kms(c.Id)
	if err != nil {
		return
	}
	ebsEncP := policy{
		Statement: []statement{
			{
				Action: []string{
					"kms:Encrypt",
					"kms:Decrypt",
					"kms:ReEncrypt",
					"kms:GenerateDataKey*",
					"kms:DescribeKey",
				},
				Resource: []string{
					c.master.KeyARN,
				},
				Effect: "Allow",
			},
			{
				Action: []string{
					"kms:CreateGrant",
				},
				Resource: []string{
					c.master.KeyARN,
				},
				Effect: "Allow",
			},
		},
	}
	ebsEncryptPolicy, err := c.CreatePolicy("ebs-encrypt-"+c.Id, ebsEncP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, ebsEncryptPolicy)
	if err != nil {
		return
	}
	secretId, err := c.secret(c.Id, kmsKey, "{}")
	if err != nil {
		return
	}
	c.master.TokenLocation = secretId
	secretReadP := policy{
		Statement: []statement{
			{
				Action: []string{
					"secretsmanager:GetSecretValue",
					"secretsmanager:DescribeSecret",
					"secretsmanager:ListSecretVersionIds",
				},
				Resource: []string{
					secretId,
				},
				Effect: "Allow",
			},
			{
				Action: []string{
					"kms:Decrypt",
				},
				Resource: []string{
					c.master.KeyARN,
				},
				Effect: "Allow",
			},
		},
	}
	secretReadPolicy, err := c.CreatePolicy("secret-read-"+c.Id, secretReadP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("node-"+c.Id, secretReadPolicy)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, secretReadPolicy)
	if err != nil {
		return
	}
	secretWriteP := policy{
		Statement: []statement{
			{
				Action: []string{
					"secretsmanager:PutSecretValue",
					"secretsmanager:UpdateSecret",
				},
				Resource: []string{
					secretId,
				},
				Effect: "Allow",
			},
		},
	}
	secretWritePolicy, err := c.CreatePolicy("secret-write-"+c.Id, secretWriteP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, secretWritePolicy)
	if err != nil {
		return
	}
	table, err := c.createTable(c.Id)
	if err != nil {
		return
	}
	tableReadP := policy{
		Statement: []statement{
			{
				Action: []string{
					"dynamodb:GetItem",
					"dynamodb:DescribeTable",
					"dynamodb:DescribeTimeToLive",
					"dynamodb:Query",
					"dynamodb:Scan",
				},
				Resource: []string{
					table,
					table+"/index/*",
				},
				Effect: "Allow",
			},
		},
	}
	tableReadPolicy, err := c.CreatePolicy("dynamo-read-"+c.Id, tableReadP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("node-"+c.Id, tableReadPolicy)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, tableReadPolicy)
	if err != nil {
		return
	}
	tableWriteP := policy{
		Statement: []statement{
			{
				Action: []string{
					"dynamodb:PutItem",
					"dynamodb:UpdateItem",
				},
				Resource: []string{
					table,
					table+"/index/*",
				},
				Effect: "Allow",
			},
		},
	}
	tableWritePolicy, err := c.CreatePolicy("dynamo-write-"+c.Id, tableWriteP)
	if err != nil {
		return
	}
	err = c.AttachPolicy("master-"+c.Id, tableWritePolicy)
	if err != nil {
		return
	}
	c.agentStore = dynalock.New(dynamodb.New(c.Cfg), c.Id, "Agent")
	err = c.uploadClusterMeta(c.master, true)
	if err != nil {
		return
	}

	err = c.createASG("master-"+c.Id+"-a", "master-"+c.Id, masterA, "master-lb-"+c.Id, 1, 1, 1, map[string]string{
		"Name": "Master - "+c.Id+" - A",
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
		"kubernetes.io/role/master": "1",
	})
	if err != nil {
		return
	}
	err = c.createASG("master-"+c.Id+"-b", "master-"+c.Id, masterB, "master-lb-"+c.Id, 1, 1, 1, map[string]string{
		"Name": "Master - "+c.Id+" - B",
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
		"kubernetes.io/role/master": "1",
	})
	if err != nil {
		return
	}
	err = c.createASG("master-"+c.Id+"-c", "master-"+c.Id, masterC, "master-lb-"+c.Id, 1, 1, 1, map[string]string{
		"Name": "Master - "+c.Id+" - C",
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
		"kubernetes.io/role/master": "1",
	})
	if err != nil {
		return
	}

	err = c.createASG("node-"+c.Id+"-a", "node-"+c.Id, nodeA, "", 1, 1, 1, map[string]string{
		"Name": "Node - "+c.Id+" - A",
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
		"kubernetes.io/role/node": "1",
	})
	if err != nil {
		return
	}
}

func (c Client) tag(ids []string, t map[string]string) {
	tags := []ec2.Tag{}

	for k, v := range t {
		tags = append(tags, ec2.Tag{
			Key: aws.String(k),
			Value: aws.String(v),
		})
	}

	tagReq := c.Ec2.CreateTagsRequest(&ec2.CreateTagsInput{
		Resources: ids,
		Tags: tags,
	})
	res, err := tagReq.Send(context.Background())
	if err != nil {
		log.Printf("Could not create tags for [%s] %v\n", ids[0], err)
		return
	}
	log.Printf("%v\n", res)
}

func (c Client) tagWithName(id string) {
	c.tag([]string{id}, map[string]string{
		"Name": c.Id,
	})
}

func (c Client) vpc(cidr string) string {
	input := &ec2.CreateVpcInput{
		CidrBlock: aws.String(cidr),
	}

	req := c.Ec2.CreateVpcRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
				default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}

	log.Printf("%v\n", result)

	inputDns := &ec2.ModifyVpcAttributeInput{
		EnableDnsSupport: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
		VpcId: aws.String(*result.Vpc.VpcId),
	}

	reqDns := c.Ec2.ModifyVpcAttributeRequest(inputDns)
	resDns, err := reqDns.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}

	log.Printf("%v\n", resDns)

	inputDns = &ec2.ModifyVpcAttributeInput{
		EnableDnsHostnames: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
		VpcId: aws.String(*result.Vpc.VpcId),
	}

	reqDns = c.Ec2.ModifyVpcAttributeRequest(inputDns)
	resDns, err = reqDns.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Printf("%v\n", resDns)

	c.tagWithName(*result.Vpc.VpcId)

	return *result.Vpc.VpcId
}

// create subnets
func (c Client) subnet(vpc string, cidr string, name string, public bool, az string) string {
	input := &ec2.CreateSubnetInput{
		CidrBlock:          aws.String(cidr),
		VpcId:              aws.String(vpc),
		AvailabilityZoneId: aws.String(az),
	}

	req := c.Ec2.CreateSubnetRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Printf("%v\n", result)

	if public {
		mapInput := &ec2.ModifySubnetAttributeInput{
			MapPublicIpOnLaunch: &ec2.AttributeBooleanValue{
				Value: aws.Bool(true),
			},
			SubnetId:            result.Subnet.SubnetId,
		}
		mapReq := c.Ec2.ModifySubnetAttributeRequest(mapInput)
		mapRes, err := mapReq.Send(context.Background())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				default:
					log.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Println(err.Error())
			}
			return ""
		}
		log.Printf("%v\n", mapRes)
	}

	tags := map[string]string{
		"Name": strings.Join([]string{name, c.Id}, " "),
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
	}
	master := false
	if master {
		tags["kubernetes.io/role/master"] = "1"
	}
	if public {
		tags["kubernetes.io/role/elb"] = "1"
	}
	c.tag([]string{*result.Subnet.SubnetId}, tags)

	return *result.Subnet.SubnetId
}

func (c Client) gateway(vpc string) string {
	input := &ec2.CreateInternetGatewayInput{}
	req := c.Ec2.CreateInternetGatewayRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}

	log.Println(result)

	assocInput := &ec2.AttachInternetGatewayInput{
		InternetGatewayId: aws.String(*result.InternetGateway.InternetGatewayId),
		VpcId:             aws.String(vpc),
	}

	assocReq := c.Ec2.AttachInternetGatewayRequest(assocInput)
	res, err := assocReq.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Println(res)

	c.tagWithName(*result.InternetGateway.InternetGatewayId)

	return *result.InternetGateway.InternetGatewayId
}

/* @TODO mark nat gateway as deprecated
func (c Client) nat(subnet string) string {
	input := &ec2.AllocateAddressInput{
		Domain: ec2.DomainTypeVpc,
	}

	req := c.Ec2.AllocateAddressRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Println(result)

	natInput := &ec2.CreateNatGatewayInput{
		AllocationId: aws.String(*result.AllocateAddressOutput.AllocationId),
		SubnetId:     aws.String(subnet),
	}

	natReq := c.Ec2.CreateNatGatewayRequest(natInput)
	natRes, err := natReq.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Printf("%v\n", natRes)

	stateInput := &ec2.DescribeNatGatewaysInput{
		NatGatewayIds: []string{*natRes.CreateNatGatewayOutput.NatGateway.NatGatewayId},
	}
	// stateReq := c.Ec2.DescribeNatGatewaysRequest(stateInput)
	err = c.Ec2.WaitUntilNatGatewayAvailable(context.Background(), stateInput)
	if err != nil {
		log.Errorf("failed to wait for nat gateway to exist, %v", err)
		return ""
	}

	c.tag([]string{*result.AllocateAddressOutput.AllocationId, *natRes.CreateNatGatewayOutput.NatGateway.NatGatewayId}, map[string]string{
		"Name": c.Id,
	})

	return *natRes.CreateNatGatewayOutput.NatGateway.NatGatewayId
}
*/

func (c Client) routeTable(vpc string, gateway string, cidr string) string {
	input := &ec2.CreateRouteTableInput{
		VpcId: aws.String(vpc),
	}

	req := c.Ec2.CreateRouteTableRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Println(result)

	inputRoute := &ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String(cidr),
		RouteTableId:         aws.String(*result.RouteTable.RouteTableId),
	}

	if strings.HasPrefix(gateway, "i-") {
		inputRoute.InstanceId = aws.String(gateway)
	} else {
		inputRoute.GatewayId = aws.String(gateway)
	}
	routeReq := c.Ec2.CreateRouteRequest(inputRoute)
	routeResult, err := routeReq.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Println(routeResult)

	c.tagWithName(*result.RouteTable.RouteTableId)
	return *result.RouteTable.RouteTableId
}

func (c Client) assocRoute(subnet string, table string) {
	input := &ec2.AssociateRouteTableInput{
		RouteTableId: aws.String(table),
		SubnetId:     aws.String(subnet),
	}

	req := c.Ec2.AssociateRouteTableRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return
	}

	log.Println(result)
}

// create security groups and rules

func (c Client) securityGroup(vpc string, name string, description string) string {
	groupName := strings.Join([]string{name, c.Id}, "-")
	input := &ec2.CreateSecurityGroupInput{
		Description: aws.String(description),
		GroupName:   aws.String(groupName),
		VpcId:       aws.String(vpc),
	}
	req := c.Ec2.CreateSecurityGroupRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}
	log.Println(result)

	tags := map[string]string{
		"Name":              strings.Join([]string{name, c.Id}," "),
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
	}
	c.tag([]string{*result.CreateSecurityGroupOutput.GroupId}, tags)
	return *result.CreateSecurityGroupOutput.GroupId
}

func (c Client) securityGroupRule(from int64, to int64, cidr string, proto string, description string) ec2.IpPermission {

	rule := ec2.IpPermission{
		IpProtocol: aws.String(proto),
	}

	if proto != "-1" {
		rule.FromPort = aws.Int64(from)
		rule.ToPort = aws.Int64(to)
	}

	if strings.HasPrefix(cidr, "sg-") {
		rule.UserIdGroupPairs = []ec2.UserIdGroupPair{
			{
				GroupId:     aws.String(cidr),
				Description: aws.String(description),
			},
		}
	} else {
		rule.IpRanges = []ec2.IpRange{
			{
				CidrIp:      aws.String(cidr),
				Description: aws.String(description),
			},
		}
	}

	return rule
}

func (c Client) securityGroupRuleApply(sg string, rules []ec2.IpPermission, dir Direction) string {
	switch dir {
	case Ingress:
		input := &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: aws.String(sg),
			IpPermissions: rules,
		}

		req := c.Ec2.AuthorizeSecurityGroupIngressRequest(input)
		result, err := req.Send(context.Background())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				default:
					log.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Println(err.Error())
			}
			return ""
		}

		log.Println(result)
	case Egress:
		input := &ec2.AuthorizeSecurityGroupEgressInput{
			GroupId: aws.String(sg),
			IpPermissions: rules,
		}

		req := c.Ec2.AuthorizeSecurityGroupEgressRequest(input)
		result, err := req.Send(context.Background())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				default:
					log.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Println(err.Error())
			}
			return ""
		}

		log.Println(result)
	}
	return ""
}

func (c Client) instance(i *Instance) (*Instance, error) {
	if i.root == 0 {
		i.root = 20
	}
	iType := ec2.InstanceTypeT3aMicro
	if i.size == "t3amedium" {
		iType = ec2.InstanceTypeT3aMedium
	} else if i.size == "t3axlarge" {
		iType = ec2.InstanceTypeT3aXlarge
	} else if i.size == "t3a2xlarge" {
		iType = ec2.InstanceTypeT3a2xlarge
	}
	input := &ec2.RunInstancesInput{
		BlockDeviceMappings: []ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/xvda"),
				Ebs: &ec2.EbsBlockDevice{
					VolumeSize: aws.Int64(i.root),
				},
			},
		},
		ImageId:      aws.String(i.ami),
		InstanceType: iType,
		KeyName:      aws.String(i.key),
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
		SecurityGroupIds: []string{
			i.sg,
		},
		SubnetId: aws.String(i.subnet),
		TagSpecifications: []ec2.TagSpecification{
			{
				ResourceType: ec2.ResourceTypeInstance,
				Tags: []ec2.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(strings.Join([]string{i.name, c.Id}, " ")),
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
			},
		},
	}

	req := c.Ec2.RunInstancesRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return nil, err
	}
	if i.nat {
		in := &ec2.ModifyInstanceAttributeInput{
			InstanceId: aws.String(*result.Instances[0].InstanceId),
			SourceDestCheck: &ec2.AttributeBooleanValue{
				Value: aws.Bool(false),
			},
		}
		natReq := c.Ec2.ModifyInstanceAttributeRequest(in)
		_, err := natReq.Send(context.Background())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				default:
					log.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Println(err.Error())
			}
			return nil, err
		}
	}

	stateInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{*result.Instances[0].InstanceId},
	}

	err = c.Ec2.WaitUntilInstanceRunning(context.Background(), stateInput)
	if err != nil {
		log.Errorf("failed to wait for instance to be running, %v", err)
		return nil, err
	}

	stateReq := c.Ec2.DescribeInstancesRequest(stateInput)
	res, err := stateReq.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return nil, err
	}

	log.Println(res)

	i.id      = *result.Instances[0].InstanceId
	if res.DescribeInstancesOutput.Reservations[0].Instances[0].PublicIpAddress != nil {
		i.public  = *res.DescribeInstancesOutput.Reservations[0].Instances[0].PublicIpAddress
	}
	i.private = *res.DescribeInstancesOutput.Reservations[0].Instances[0].PrivateIpAddress

	return i, nil
}

func (c Client) instanceProfile(name string) (string, error) {
	svc := iam.New(c.Cfg)
	input := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(name),
	}
	req := svc.CreateInstanceProfileRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				log.Error(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				log.Error(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return "", err
	}

	/*
	inputGet := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(name),
	}
	*/

	/*
	req := svc.GetInstanceProfileRequest(inputGet)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return "", nil
	}
	*/

	log.Info(result)

	return *result.InstanceProfile.InstanceProfileName, nil
}

func (c Client) addRoleInstance(name, role string) error {
	svc := iam.New(c.Cfg)
	input := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(name),
		RoleName:            aws.String(role),
	}

	req := svc.AddRoleToInstanceProfileRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeEntityAlreadyExistsException:
				log.Error(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				log.Error(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeUnmodifiableEntityException:
				log.Error(iam.ErrCodeUnmodifiableEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return nil
	}

	log.Info(result)
	return nil
}


func (c Client) kms(name string) (string, string, error) {
	svc := kms.New(c.Cfg)
	input := &kms.CreateKeyInput{
		Tags: []kms.Tag{
			{
				TagKey:   aws.String(strings.Join([]string{"kubernetes.io/cluster/", c.Id}, "")),
				TagValue: aws.String("owned"),
			},
			{
				TagKey:   aws.String("Name"),
				TagValue: aws.String(c.Id),
			},
		},
	}

	req := svc.CreateKeyRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeMalformedPolicyDocumentException:
				log.Println(kms.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				log.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidArnException:
				log.Println(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeUnsupportedOperationException:
				log.Println(kms.ErrCodeUnsupportedOperationException, aerr.Error())
			case kms.ErrCodeKMSInternalException:
				log.Println(kms.ErrCodeKMSInternalException, aerr.Error())
			case kms.ErrCodeLimitExceededException:
				log.Println(kms.ErrCodeLimitExceededException, aerr.Error())
			case kms.ErrCodeTagException:
				log.Println(kms.ErrCodeTagException, aerr.Error())
			case kms.ErrCodeCustomKeyStoreNotFoundException:
				log.Println(kms.ErrCodeCustomKeyStoreNotFoundException, aerr.Error())
			case kms.ErrCodeCustomKeyStoreInvalidStateException:
				log.Println(kms.ErrCodeCustomKeyStoreInvalidStateException, aerr.Error())
			case kms.ErrCodeCloudHsmClusterInvalidConfigurationException:
				log.Println(kms.ErrCodeCloudHsmClusterInvalidConfigurationException, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {

			log.Println(err.Error())
		}
		return "", "", err
	}

	log.Println(result)
	return *result.KeyMetadata.KeyId, *result.KeyMetadata.Arn, nil
}

func (c Client) secret(name string, key string, secret string) (string, error) {

	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.CreateSecretInput{
		Description:        aws.String(strings.Join([]string{c.Id, " ", name}, "")),
		Name:               aws.String(name),
		SecretString:       aws.String(secret),
		KmsKeyId:           aws.String(key),
		Tags: []secretsmanager.Tag{
			{
				Key:   aws.String(strings.Join([]string{"kubernetes.io/cluster/", c.Id}, "")),
				Value: aws.String("owned"),
			},
			{
				Key:   aws.String(strings.Join([]string{"kubernetesCluster", c.Id}, "")),
				Value: aws.String(c.Id),
			},
			{
				Key:   aws.String("Name"),
				Value: aws.String(name),
			},
		},
	}

	req := svc.CreateSecretRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeLimitExceededException:
				log.Println(secretsmanager.ErrCodeLimitExceededException, aerr.Error())
			case secretsmanager.ErrCodeEncryptionFailure:
				log.Println(secretsmanager.ErrCodeEncryptionFailure, aerr.Error())
			case secretsmanager.ErrCodeResourceExistsException:
				log.Println(secretsmanager.ErrCodeResourceExistsException, aerr.Error())
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeMalformedPolicyDocumentException:
				log.Println(secretsmanager.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			case secretsmanager.ErrCodePreconditionNotMetException:
				log.Println(secretsmanager.ErrCodePreconditionNotMetException, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {

			log.Println(err.Error())
		}
		return "", err
	}

	log.Println(result)

	return *result.ARN, nil
}

func (c Client) key(name string, s ssh.Ssh) string {
	input := &ec2.ImportKeyPairInput{
		KeyName: aws.String(name),
		PublicKeyMaterial: s.PublicKey,
	}

	req := c.Ec2.ImportKeyPairRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return ""
	}

	log.Println(result)
	return *result.ImportKeyPairOutput.KeyName
}

func (c Client) createASG(name, template, subnet, lb string, min, max, desired int64, tags map[string]string) error {
	svc := autoscaling.New(c.Cfg)
	t := []autoscaling.Tag{}
	for k, v := range tags {
		t = append(t, autoscaling.Tag{
			Key: aws.String(k),
			Value: aws.String(v),
			PropagateAtLaunch: aws.Bool(true),
		})
	}
	input := &autoscaling.CreateAutoScalingGroupInput{
		AutoScalingGroupName:    aws.String(name),
		LaunchConfigurationName: aws.String(template),
		MaxInstanceLifetime:     aws.Int64(604800), // 1 week
		MaxSize:                 aws.Int64(max),
		MinSize:                 aws.Int64(min),
		DesiredCapacity:         aws.Int64(desired),
		VPCZoneIdentifier:       aws.String(subnet),
		Tags:                    t,
	}
	if lb != "" {
		input.LoadBalancerNames = []string{lb}
	}

	req := svc.CreateAutoScalingGroupRequest(input)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case autoscaling.ErrCodeAlreadyExistsFault:
				log.Error(autoscaling.ErrCodeAlreadyExistsFault, aerr.Error())
			case autoscaling.ErrCodeLimitExceededFault:
				log.Error(autoscaling.ErrCodeLimitExceededFault, aerr.Error())
			case autoscaling.ErrCodeResourceContentionFault:
				log.Error(autoscaling.ErrCodeResourceContentionFault, aerr.Error())
			case autoscaling.ErrCodeServiceLinkedRoleFailure:
				log.Error(autoscaling.ErrCodeServiceLinkedRoleFailure, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return err
	}

	return  nil
}

func (c Client) createLaunchTemplate(name, size, ami, role, key, sg, data string) (string, error) {
	svc := autoscaling.New(c.Cfg)
	input := &autoscaling.CreateLaunchConfigurationInput{
		IamInstanceProfile:      aws.String(role),
		ImageId:                 aws.String(ami),
		BlockDeviceMappings:     []autoscaling.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/xvda"),
				Ebs: &autoscaling.Ebs{
					VolumeSize: aws.Int64(80),
					VolumeType: aws.String("gp2"),
				},
			},
		},
		InstanceType:            aws.String(size),
		LaunchConfigurationName: aws.String(name),
		KeyName:                 aws.String(key),
		UserData:                aws.String(base64.StdEncoding.EncodeToString([]byte(data))),
		SecurityGroups: []string{
			sg,
		},
	}

	var result *autoscaling.CreateLaunchConfigurationResponse
	var err error
	var count int
	for {
		req := svc.CreateLaunchConfigurationRequest(input)
		result, err = req.Send(context.Background())
		log.Info(result)
		if err != nil {
			log.Errorf("failed to create launch config %v", err)
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case autoscaling.ErrCodeAlreadyExistsFault:
					log.Error(autoscaling.ErrCodeAlreadyExistsFault, aerr.Error())
				case autoscaling.ErrCodeLimitExceededFault:
					log.Error(autoscaling.ErrCodeLimitExceededFault, aerr.Error())
				case autoscaling.ErrCodeResourceContentionFault:
					log.Error(autoscaling.ErrCodeResourceContentionFault, aerr.Error())
				default:
					log.Error(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Error(err.Error())
			}
			count++
			if count > 15 {
				return "", err
			}
			time.Sleep(5 * time.Second)
		} else {
			break
		}
	}

	return result.String(), nil
}

/* @DEPRECATED mark for removal
func (c Client) attachClusterAPI(lb, asg string) error {
	svc := autoscaling.New(c.Cfg)
	input := &autoscaling.AttachLoadBalancersInput{
		AutoScalingGroupName: aws.String(asg),
		LoadBalancerNames: []string{
			lb,
		},
	}

	req := svc.AttachLoadBalancersRequest(input)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case autoscaling.ErrCodeResourceContentionFault:
				log.Error(autoscaling.ErrCodeResourceContentionFault, aerr.Error())
			case autoscaling.ErrCodeServiceLinkedRoleFailure:
				log.Error(autoscaling.ErrCodeServiceLinkedRoleFailure, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return err
	}
	return nil
}
*/

func (c Client) loadBalancer(name string, sg string, subnets []string) (string, error){
	svc := elasticloadbalancing.New(c.Cfg)
	input := &elasticloadbalancing.CreateLoadBalancerInput{
		Listeners: []elasticloadbalancing.Listener{
			{
				InstancePort:     aws.Int64(6443),
				InstanceProtocol: aws.String("TCP"),
				LoadBalancerPort: aws.Int64(6443),
				Protocol:         aws.String("TCP"),
			},
		},
		LoadBalancerName: aws.String(name),
		Scheme:           aws.String("internal"),
		SecurityGroups: []string{
			sg,
		},
		Subnets: subnets,
	}

	req := svc.CreateLoadBalancerRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case elasticloadbalancing.ErrCodeDuplicateAccessPointNameException:
				log.Println(elasticloadbalancing.ErrCodeDuplicateAccessPointNameException, aerr.Error())
			case elasticloadbalancing.ErrCodeTooManyAccessPointsException:
				log.Println(elasticloadbalancing.ErrCodeTooManyAccessPointsException, aerr.Error())
			case elasticloadbalancing.ErrCodeCertificateNotFoundException:
				log.Println(elasticloadbalancing.ErrCodeCertificateNotFoundException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidConfigurationRequestException:
				log.Println(elasticloadbalancing.ErrCodeInvalidConfigurationRequestException, aerr.Error())
			case elasticloadbalancing.ErrCodeSubnetNotFoundException:
				log.Println(elasticloadbalancing.ErrCodeSubnetNotFoundException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidSubnetException:
				log.Println(elasticloadbalancing.ErrCodeInvalidSubnetException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidSecurityGroupException:
				log.Println(elasticloadbalancing.ErrCodeInvalidSecurityGroupException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidSchemeException:
				log.Println(elasticloadbalancing.ErrCodeInvalidSchemeException, aerr.Error())
			case elasticloadbalancing.ErrCodeTooManyTagsException:
				log.Println(elasticloadbalancing.ErrCodeTooManyTagsException, aerr.Error())
			case elasticloadbalancing.ErrCodeDuplicateTagKeysException:
				log.Println(elasticloadbalancing.ErrCodeDuplicateTagKeysException, aerr.Error())
			case elasticloadbalancing.ErrCodeUnsupportedProtocolException:
				log.Println(elasticloadbalancing.ErrCodeUnsupportedProtocolException, aerr.Error())
			case elasticloadbalancing.ErrCodeOperationNotPermittedException:
				log.Println(elasticloadbalancing.ErrCodeOperationNotPermittedException, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return "", err
	}

	log.Println(result)

	return *result.CreateLoadBalancerOutput.DNSName, nil
}

func (c Client) bucket(name string) (string, error) {
	svc := s3.New(c.Cfg)
	input := &s3.CreateBucketInput{
		Bucket: aws.String(name),
		ACL: s3.BucketCannedACLPublicRead,
		//CreateBucketConfiguration: s3.CreateBucketConfiguration{
		//	LocationConstraint:
		//},
	}

	req := svc.CreateBucketRequest(input)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyExists:
				log.Println(s3.ErrCodeBucketAlreadyExists, aerr.Error())
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				log.Println(s3.ErrCodeBucketAlreadyOwnedByYou, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return "", err
	}
	// get bucket

	return "arn:aws:s3:::"+name, nil
}

func (c Client) createTable(name string) (string, error) {
	svc := dynamodb.New(c.Cfg)
	input := &dynamodb.CreateTableInput{
		AttributeDefinitions: []dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: dynamodb.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("name"),
				AttributeType: dynamodb.ScalarAttributeTypeS,
			},
		},
		KeySchema: []dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       dynamodb.KeyTypeHash,
			},
			{
				AttributeName: aws.String("name"),
				KeyType:       dynamodb.KeyTypeRange,
			},
		},
		BillingMode: "PAY_PER_REQUEST",
		SSESpecification: &dynamodb.SSESpecification{
			Enabled: aws.Bool(true),
		},
		TableName: aws.String(name),
	}

	req := svc.CreateTableRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceInUseException:
				log.Println(dynamodb.ErrCodeResourceInUseException, aerr.Error())
			case dynamodb.ErrCodeLimitExceededException:
				log.Println(dynamodb.ErrCodeLimitExceededException, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				log.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {

			log.Println(err.Error())
		}
		return "", err
	}
	log.Println(result)
	reqS := svc.DescribeTableRequest(&dynamodb.DescribeTableInput{
			TableName: aws.String(name),
		})
	count := 0
	for {
		resS, err := reqS.Send(context.Background())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case dynamodb.ErrCodeResourceNotFoundException:
					log.Println(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
				case dynamodb.ErrCodeInternalServerError:
					log.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
				default:
					log.Println(aerr.Error())
				}
			} else {
				log.Println(err.Error())
			}
			return "", err
		}
		status := resS.DescribeTableOutput.Table.TableStatus
		log.Println(status)
		if status == dynamodb.TableStatusActive {
			log.Println("Done")
			break
		}
		time.Sleep(500 * time.Millisecond)
		count++
		if count > 10 {
			return "", err
		}
	}

	update := &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(name),
		TimeToLiveSpecification: &dynamodb.TimeToLiveSpecification{
			Enabled: aws.Bool(true),
			AttributeName: aws.String("expires"),
		},
	}
	reqU := svc.UpdateTimeToLiveRequest(update)
	_, err = reqU.Send(context.Background())
	if err != nil {
		log.Println(err.Error())
		return "", err
	}
	// log.Println(res)
	return *result.TableDescription.TableArn, nil
}

func getCert(address string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Errorf("failed to connect to %s %v", address, err)
		return nil, err
	}
	defer conn.Close()
	/*
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
	*/
	return conn.ConnectionState().PeerCertificates[0], nil
}

func (c Client) oidcIAM(url string) (string, error) {

	addr := strings.ReplaceAll(url, "https://", "")
	idx  := strings.IndexAny(addr, "/")
	if idx > 0 {
		addr = addr[0:idx]
	}
	cert, err := getCert(addr+":443")
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(cert.Raw)
	thumb := hex.EncodeToString(sum[:])
	svc := iam.New(c.Cfg)
	input := &iam.CreateOpenIDConnectProviderInput{
		ClientIDList: []string{
			"sts.amazonaws.com",
		},
		ThumbprintList: []string{
			thumb,
		},
		Url: aws.String(url),
	}

	req := svc.CreateOpenIDConnectProviderRequest(input)
	result, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeInvalidInputException:
				log.Println(iam.ErrCodeInvalidInputException, aerr.Error())
			case iam.ErrCodeEntityAlreadyExistsException:
				log.Println(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				log.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
		return "", err
	}

	return *result.OpenIDConnectProviderArn, nil
}
