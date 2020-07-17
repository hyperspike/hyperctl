package aws

import (
	"context"
	"fmt"
	"strings"

	"hyperspike.io/eng/hyperctl/auth/ssh"
	"hyperspike.io/eng/hyperctl/bootstrap/bastion"
	"hyperspike.io/eng/hyperctl/templates/kubeadm"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	_ "github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
)


type Direction string
const (
	Ingress Direction = "ingress"
	Egress = "egress"
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
	vpc := c.vpc("10.20.0.0/16")
	podCidr := "10.20.128.0/20"

	masterA  := c.subnet(vpc, "10.20.140.0/24", "Master - 0", false, "use2-az1")
	masterB  := c.subnet(vpc, "10.20.141.0/24", "Master - 1", false, "use2-az2")
	masterC  := c.subnet(vpc, "10.20.142.0/24", "Master - 2", false, "use2-az3")
	nodeA    := c.subnet(vpc, "10.20.128.0/22", "Nodes - 0", false, "use2-az1")
	nodeB    := c.subnet(vpc, "10.20.132.0/22", "Nodes - 1", false, "use2-az2")
	nodeC    := c.subnet(vpc, "10.20.136.0/22", "Nodes - 2", false, "use2-az3")
	edgeA := c.subnet(vpc, "10.20.0.0/26",   "Edge - 0", true, "use2-az1")
	edgeB := c.subnet(vpc, "10.20.0.64/26",  "Edge - 1", true, "use2-az2")
	edgeC := c.subnet(vpc, "10.20.0.128/26", "Edge - 2", true, "use2-az3")

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
	fwA, _ := c.instance(&Instance{name:"Firewall - 1", ami:"ami-008a61f78ba92b950", key:bastionKey, subnet:edgeA, sg:edgeSg, nat: true})

	natRoute := c.routeTable(vpc, fwA.id, "0.0.0.0/0")
	c.assocRoute(masterA, natRoute)
	c.assocRoute(masterB, natRoute)
	c.assocRoute(masterC, natRoute)
	c.assocRoute(nodeA, natRoute)
	c.assocRoute(nodeB, natRoute)
	c.assocRoute(nodeC, natRoute)
	fwHostA := bastion.New(fwA.public + "/32" , 22, key.PrivateKey, "alpine")
	fwHostA.Run([]string{
		"sudo su -c 'echo http://dl-cdn.alpinelinux.org/alpine/edge/main/ >> /etc/apk/repositories'",
		"sudo su -c 'echo http://dl-cdn.alpinelinux.org/alpine/edge/community/ >> /etc/apk/repositories'",
		"sudo apk update",
		"sudo apk add -u openssh iptables suricata",
		`sudo  sed -i -e 's/^\(AllowTcpForwarding\)\s\+\w\+/\1 yes/' /etc/ssh/sshd_config`,
		"sudo rc-service sshd restart",
		"sudo rc-update add suricata default",
		"sudo rc-service suricata start",
		"sudo su -c 'echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf'",
		"sudo sysctl -p",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.20.140.0/24 -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.20.141.0/24 -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.20.142.0/24 -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.20.128.0/22 -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.20.132.0/22 -j MASQUERADE",
		"sudo iptables -t nat -A POSTROUTING -o eth0 -s 10.20.136.0/22 -j MASQUERADE",
		"sudo iptables -I INPUT -j NFQUEUE",
		"sudo iptables -I OUTPUT -j NFQUEUE",
		"sudo iptables -t nat -I INPUT -j NFQUEUE",
		"sudo iptables -t nat -I OUTPUT -j NFQUEUE",
		"sudo rc-service iptables save",
	})
	masterInsA, _ := c.instance(&Instance{name:"Master - 1", ami:"ami-004a4406fef940ebd", key:bastionKey, subnet:masterA, sg:masterSg, root: 40, size: "t3amedium"})
	masterHostA := bastion.New(masterInsA.private + "/32", 22, key.PrivateKey, "alpine")
	fwHostA.Reconnect()
	masterHostA.Bastion(fwHostA)
	elb, _ := c.loadBalancer("Master ELB", masterLbSg, []string{masterA, masterB, masterC})
	k := kubeadm.New(masterInsA.private, "us-east-2", elb, "hyperspike.east2", "10.20.128.0/20", "172.16.0.0/18")
	kubeadmConf, _ := k.KubeadmYaml()
	masterHostA.Run([]string{
		"sudo resize2fs /dev/xvda",
		"sudo su -c 'uuidgen|tr -d - > /etc/machine-id'",
		"chmod +x /tmp/init-master.sh",
		"chmod +x /tmp/up.sh",
		"sudo su -c 'hostname -f > /etc/hostname'",
		"sudo rc-service hostname restart",
		"echo -e '" + kubeadmConf + "' > kubeadm.conf",
		"mkdir kustomize",
		"sudo kubeadm init --cri-socket /run/crio/crio.sock --config kubeadm.conf --upload-certs --skip-phases=preflight,addon/kube-proxy -k kustomize",
	})
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
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
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
					fmt.Println(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				fmt.Println(err.Error())
			}
			return nil, err
		}
	}

	stateInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{*result.Instances[0].InstanceId},
	}

	err = c.Ec2.WaitUntilInstanceRunning(context.Background(), stateInput)
	if err != nil {
		fmt.Errorf("failed to wait for instance to be running, %v", err)
		return nil, err
	}

	stateReq := c.Ec2.DescribeInstancesRequest(stateInput)
	res, err := stateReq.Send(context.Background())
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
		return nil, err
	}

	fmt.Println(res)

	i.id      = *result.Instances[0].InstanceId
	if res.DescribeInstancesOutput.Reservations[0].Instances[0].PublicIpAddress != nil {
		i.public  = *res.DescribeInstancesOutput.Reservations[0].Instances[0].PublicIpAddress
	}
	i.private = *res.DescribeInstancesOutput.Reservations[0].Instances[0].PrivateIpAddress

	return i, nil
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
				fmt.Println(elasticloadbalancing.ErrCodeDuplicateAccessPointNameException, aerr.Error())
			case elasticloadbalancing.ErrCodeTooManyAccessPointsException:
				fmt.Println(elasticloadbalancing.ErrCodeTooManyAccessPointsException, aerr.Error())
			case elasticloadbalancing.ErrCodeCertificateNotFoundException:
				fmt.Println(elasticloadbalancing.ErrCodeCertificateNotFoundException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidConfigurationRequestException:
				fmt.Println(elasticloadbalancing.ErrCodeInvalidConfigurationRequestException, aerr.Error())
			case elasticloadbalancing.ErrCodeSubnetNotFoundException:
				fmt.Println(elasticloadbalancing.ErrCodeSubnetNotFoundException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidSubnetException:
				fmt.Println(elasticloadbalancing.ErrCodeInvalidSubnetException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidSecurityGroupException:
				fmt.Println(elasticloadbalancing.ErrCodeInvalidSecurityGroupException, aerr.Error())
			case elasticloadbalancing.ErrCodeInvalidSchemeException:
				fmt.Println(elasticloadbalancing.ErrCodeInvalidSchemeException, aerr.Error())
			case elasticloadbalancing.ErrCodeTooManyTagsException:
				fmt.Println(elasticloadbalancing.ErrCodeTooManyTagsException, aerr.Error())
			case elasticloadbalancing.ErrCodeDuplicateTagKeysException:
				fmt.Println(elasticloadbalancing.ErrCodeDuplicateTagKeysException, aerr.Error())
			case elasticloadbalancing.ErrCodeUnsupportedProtocolException:
				fmt.Println(elasticloadbalancing.ErrCodeUnsupportedProtocolException, aerr.Error())
			case elasticloadbalancing.ErrCodeOperationNotPermittedException:
				fmt.Println(elasticloadbalancing.ErrCodeOperationNotPermittedException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return "", err
	}

	fmt.Println(result)

	return *result.CreateLoadBalancerOutput.DNSName, nil
}

// create Bastion

// IPSec

// Kube Cluster

// Pull KubeConfig

// CAPI - Bootstrap

// Gitifold on mgmt cluster


