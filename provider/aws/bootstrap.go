package aws

import (
	"context"
	"fmt"
	"strings"

	"hyperspike.io/eng/hyperctl/auth/ssh"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	_ "github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)


type Direction string
const (
	Ingress Direction = "ingress"
	Egress = "egress"
)


func (c Client) CreateCluster() {
	vpc := c.vpc("10.20.0.0/16")
	podCidr := "10.20.128.0/20"

	masterA  := c.subnet(vpc, "10.20.140.0/24", "Master - 0", false, "use2-az1")
	masterB  := c.subnet(vpc, "10.20.141.0/24", "Master - 1", false, "use2-az2")
	masterC  := c.subnet(vpc, "10.20.142.0/24", "Master - 2", false, "use2-az3")
	nodeA    := c.subnet(vpc, "10.20.128.0/22", "Nodes - 0", false, "use2-az1")
	nodeB    := c.subnet(vpc, "10.20.132.0/22", "Nodes - 1", false, "use2-az2")
	nodeC    := c.subnet(vpc, "10.20.136.0/22", "Nodes - 2", false, "use2-az3")
	/*
	ingressA := c.subnet(vpc, "10.20.146.0/24", "Ingress - 0", true, "use2-az1")
	ingressB := c.subnet(vpc, "10.20.147.0/24", "Ingress - 1", true, "use2-az2")
	ingressC := c.subnet(vpc, "10.20.148.0/24", "Ingress - 2", true, "use2-az3")
	*/
	edgeA := c.subnet(vpc, "10.20.0.0/26",   "Edge - 0", true, "use2-az1")
	edgeB := c.subnet(vpc, "10.20.0.64/26",  "Edge - 1", true, "use2-az2")
	edgeC := c.subnet(vpc, "10.20.0.128/26", "Edge - 2", true, "use2-az3")

	gw  := c.gateway(vpc)

	gwRoute  := c.routeTable(vpc, gw,  "0.0.0.0/0")
	c.assocRoute(edgeA, gwRoute)
	c.assocRoute(edgeB, gwRoute)
	c.assocRoute(edgeC, gwRoute)
	/*
	c.assocRoute(ingressA, gwRoute)
	c.assocRoute(ingressB, gwRoute)
	c.assocRoute(ingressC, gwRoute)
	*/

	/*
	nat := c.nat(edgeA)
	*/

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
	c.securityGroupRuleApply(edgeSg, []ec2.IpPermission{edgeEgress}, Egress)

	c.securityGroupRuleApply(edgeSg, edgeIngress, Ingress)
	c.securityGroupRuleApply(masterSg, []ec2.IpPermission{edgeEgress}, Egress)
	c.securityGroupRuleApply(masterLbSg, []ec2.IpPermission{edgeEgress}, Egress)
	c.securityGroupRuleApply(nodeSg, []ec2.IpPermission{edgeEgress}, Egress)

	masterIngress := []ec2.IpPermission{}
	masterIngress = append(masterIngress, c.securityGroupRule(6443, 6443, podCidr, "tcp", "Allow pods to get API info"))
	masterIngress = append(masterIngress, c.securityGroupRule(443, 443, podCidr, "tcp", "Allow pods to get API info"))
	masterIngress = append(masterIngress, c.securityGroupRule(53, 53, podCidr, "udp", "Allow pods to get DNS"))
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
	key.WritePrivateKey("bastion")
	bastionKey := c.key("bastion", key)
	fwA := c.instance("Firewall - 1", "ami-008a61f78ba92b950", bastionKey, edgeA, edgeSg)

	natRoute := c.routeTable(vpc, fwA, "0.0.0.0/0")
	c.assocRoute(masterA, natRoute)
	c.assocRoute(masterB, natRoute)
	c.assocRoute(masterC, natRoute)
	c.assocRoute(nodeA, natRoute)
	c.assocRoute(nodeB, natRoute)
	c.assocRoute(nodeC, natRoute)
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
		fmt.Printf("Could not create tags for [%s] %v\n", ids[0], err)
		return
	}
	fmt.Printf("%v\n", res)
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

	reqDns := c.Ec2.ModifyVpcAttributeRequest(inputDns)
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

	reqDns = c.Ec2.ModifyVpcAttributeRequest(inputDns)
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
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return ""
		}
		fmt.Printf("%v\n", mapRes)
	}

	tags := map[string]string{
		"Name": strings.Join([]string{name, c.Id}, " "),
		"KubernetesCluster": c.Id,
		strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}

	fmt.Println(result)

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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Println(res)

	c.tagWithName(*result.InternetGateway.InternetGatewayId)

	return *result.InternetGateway.InternetGatewayId
}

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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Println(result)

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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Printf("%v\n", natRes)

	stateInput := &ec2.DescribeNatGatewaysInput{
		NatGatewayIds: []string{*natRes.CreateNatGatewayOutput.NatGateway.NatGatewayId},
	}
	// stateReq := c.Ec2.DescribeNatGatewaysRequest(stateInput)
	err = c.Ec2.WaitUntilNatGatewayAvailable(context.Background(), stateInput)
	if err != nil {
		fmt.Errorf("failed to wait for bucket exists, %v", err)
		return ""
	}

	c.tag([]string{*result.AllocateAddressOutput.AllocationId, *natRes.CreateNatGatewayOutput.NatGateway.NatGatewayId}, map[string]string{
		"Name": c.Id,
	})

	return *natRes.CreateNatGatewayOutput.NatGateway.NatGatewayId
}

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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Println(result)

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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Println(routeResult)

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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)
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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}
	fmt.Println(result)

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
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return ""
		}

		fmt.Println(result)
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
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return ""
		}

		fmt.Println(result)
	}
	return ""
}

func (c Client) instance(name string, ami string, keyPair string, subnet string, sg string) string {
	input := &ec2.RunInstancesInput{
		BlockDeviceMappings: []ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/xvda"),
				Ebs: &ec2.EbsBlockDevice{
					VolumeSize: aws.Int64(20),
				},
			},
		},
		ImageId:      aws.String(ami),
		InstanceType: ec2.InstanceTypeT3aMicro,
		KeyName:      aws.String(keyPair),
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
		SecurityGroupIds: []string{
			sg,
		},
		SubnetId: aws.String(subnet),
		TagSpecifications: []ec2.TagSpecification{
			{
				ResourceType: ec2.ResourceTypeInstance,
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
			},
		},
	}

	req := c.Ec2.RunInstancesRequest(input)
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
	
	stateInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{*result.Instances[0].InstanceId},
	}
	// stateReq := c.Ec2.DescribeNatGatewaysRequest(stateInput)
	err = c.Ec2.WaitUntilInstanceRunning(context.Background(), stateInput)
	if err != nil {
		fmt.Errorf("failed to wait for bucket exists, %v", err)
		return ""
	}

	fmt.Println(result)
	return *result.Instances[0].InstanceId
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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return ""
	}

	fmt.Println(result)
	return *result.ImportKeyPairOutput.KeyName
}
// create Bastion

// IPSec

// Kube Cluster

// Pull KubeConfig

// CAPI - Bootstrap

// Gitifold on mgmt cluster


