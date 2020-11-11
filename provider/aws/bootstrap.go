package aws

import (
	"crypto/tls"
	"crypto/x509"
	// #nosec
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"

	"bytes"
	"context"
	"net"
	"strings"
	"time"
	"encoding/base64"
	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/andy2046/rund"

	"hyperspike.io/hyperctl"
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

	/* state that will need to be destroyed
	 *
	 * VPC
	 * loadbalancer
	 * autoscaling groups
	 * firewall nodes
	 * launch templates
	 * ssh key
	 * KMS key
	 * secret
	 * dynamo table
	 * IAM roles
	 * IAM profiles
	 * IAM identity provider
	 */


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

	run := rund.New()

	var key *ssh.Ssh
	sshFn := rund.NewFuncOperator(func () error {
		key = ssh.New(4096)
		err = key.WritePrivateKey("bastion-"+c.Id)
		if err != nil {
			return err
		}
		bastionKey := c.key(c.Id, key)
		// throw away error as local
		_ = c.saveState("bastionKey", []string{bastionKey}, false)
		return nil
	})
	run.AddNode("ssh-keys", sshFn)

	vpcFn := rund.NewFuncOperator(func() error {
		vpc := c.vpc(vpcCidr.String())
		if vpc == "" {
			return errors.New("Failed to create VPC")
		}
		if err := c.saveState("vpc", []string{vpc}, true) ; err != nil {
			return err
		}
		return nil
	})
	run.AddNode("vpc", vpcFn)
	run.AddEdge("table", "vpc")

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

	azsFn := rund.NewFuncOperator(func() error {
		azs, err := c.azs()
		if err != nil {
			return err
		}
		_ = c.saveState("azs", azs, false)
		return nil
	})
	run.AddNode("azs", azsFn)

	masterASubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		masterA := c.subnet(vpc[0], masterACidr.String(), "Master - 0", false, azs[0])
		if masterA == "" {
			return errors.New("failed to create Master A subnet")
		}
		_ = c.saveState("masterA", []string{masterA}, false)
		return nil
	})
	run.AddNode("masterASubnet", masterASubnetFn)
	run.AddEdge("vpc", "masterASubnet")
	run.AddEdge("azs", "masterASubnet")
	masterBSubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		masterB := c.subnet(vpc[0], masterBCidr.String(), "Master - 1", false, azs[1])
		if masterB == "" {
			return errors.New("failed to create Master B subnet")
		}
		_ = c.saveState("masterB", []string{masterB}, false)
		return nil
	})
	run.AddNode("masterBSubnet", masterBSubnetFn)
	run.AddEdge("vpc", "masterBSubnet")
	run.AddEdge("azs", "masterBSubnet")
	masterCSubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		masterC := c.subnet(vpc[0], masterCCidr.String(), "Master - 2", false, azs[2])
		if masterC == "" {
			return errors.New("failed to create Master C subnet")
		}
		_ = c.saveState("masterC", []string{masterC}, false)
		return nil
	})
	run.AddNode("masterCSubnet", masterCSubnetFn)
	run.AddEdge("vpc", "masterCSubnet")
	run.AddEdge("azs", "masterCSubnet")
	nodeASubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		nodeA   := c.subnet(vpc[0], nodeACidr.String(), "Nodes - 0", false, azs[0])
		if nodeA == "" {
			return errors.New("failed to create Node A subnet")
		}
		_ = c.saveState("nodeA", []string{nodeA}, false)
		return nil
	})
	run.AddNode("nodeASubnet", nodeASubnetFn)
	run.AddEdge("vpc", "nodeASubnet")
	run.AddEdge("azs", "nodeASubnet")
	nodeBSubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		nodeB   := c.subnet(vpc[0], nodeBCidr.String(), "Nodes - 1", false, azs[1])
		if nodeB == "" {
			return errors.New("failed to create Node B subnet")
		}
		_ = c.saveState("nodeB", []string{nodeB}, false)
		return nil
	})
	run.AddNode("nodeBSubnet", nodeBSubnetFn)
	run.AddEdge("vpc", "nodeBSubnet")
	run.AddEdge("azs", "nodeBSubnet")
	nodeCSubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		nodeC   := c.subnet(vpc[0], nodeCCidr.String(), "Nodes - 2", false, azs[2])
		if nodeC == "" {
			return errors.New("failed to create Node C subnet")
		}
		_ = c.saveState("nodeC", []string{nodeC}, false)
		return nil
	})
	run.AddNode("nodeCSubnet", nodeCSubnetFn)
	run.AddEdge("vpc", "nodeCSubnet")
	run.AddEdge("azs", "nodeCSubnet")
	edgeASubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		edgeA   := c.subnet(vpc[0], edgeACidr.String(), "Edge - 0", true, azs[0])
		if edgeA == "" {
			return errors.New("failed to create Edge A subnet")
		}
		_ = c.saveState("edgeA", []string{edgeA}, false)
		return nil
	})
	run.AddNode("edgeASubnet", edgeASubnetFn)
	run.AddEdge("vpc", "edgeASubnet")
	run.AddEdge("azs", "edgeASubnet")
	edgeBSubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		edgeB   := c.subnet(vpc[0], edgeBCidr.String(), "Edge - 1", true, azs[1])
		if edgeB == "" {
			return errors.New("failed to create Edge B subnet")
		}
		_ = c.saveState("edgeB", []string{edgeB}, false)
		return nil
	})
	run.AddNode("edgeBSubnet", edgeBSubnetFn)
	run.AddEdge("vpc", "edgeBSubnet")
	run.AddEdge("azs", "edgeBSubnet")
	edgeCSubnetFn := rund.NewFuncOperator(func () error {
		vpc, _ := c.getState("vpc", false)
		azs, _ := c.getState("azs", false)
		edgeC   := c.subnet(vpc[0], edgeCCidr.String(), "Edge - 2", true, azs[2])
		if edgeC == "" {
			return errors.New("failed to create Edge C subnet")
		}
		_ = c.saveState("edgeC", []string{edgeC}, false)
		return nil
	})
	run.AddNode("edgeCSubnet", edgeCSubnetFn)
	run.AddEdge("vpc", "edgeCSubnet")
	run.AddEdge("azs", "edgeCSubnet")

	createGWFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		gw  := c.gateway(vpc[0])
		if gw == "" {
			return errors.New("failed to create internet gw")
		}
		_ = c.saveState("gw", []string{gw}, false)
		return nil
	})
	run.AddNode("createGW", createGWFn)
	run.AddEdge("vpc", "createGW")

	createRouteFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		gw, _ := c.getState("gw", false)
		gwRoute  := c.routeTable(vpc[0], gw[0],  "0.0.0.0/0")
		if gwRoute == "" {
			return errors.New("failed to create internet gw Route")
		}
		_ = c.saveState("gwRoute", []string{gwRoute}, false)
		return nil
	})
	run.AddNode("createRoute", createRouteFn)
	run.AddEdge("createGW", "createRoute")

	assocRouteEdgeA := rund.NewFuncOperator(func() error {
		edgeA, _ := c.getState("edgeA", false)
		gwRoute, _ := c.getState("gwRoute", false)
		c.assocRoute(edgeA[0], gwRoute[0])
		return nil
	})
	run.AddNode("assocRouteEdgeA", assocRouteEdgeA)
	run.AddEdge("edgeASubnet", "assocRouteEdgeA")
	run.AddEdge("createRoute", "assocRouteEdgeA")
	assocRouteEdgeB := rund.NewFuncOperator(func() error {
		edgeB, _ := c.getState("edgeB", false)
		gwRoute, _ := c.getState("gwRoute", false)
		c.assocRoute(edgeB[0], gwRoute[0])
		return nil
	})
	run.AddNode("assocRouteEdgeB", assocRouteEdgeB)
	run.AddEdge("edgeBSubnet", "assocRouteEdgeB")
	run.AddEdge("createRoute", "assocRouteEdgeB")
	assocRouteEdgeC:= rund.NewFuncOperator(func() error {
		edgeC, _ := c.getState("edgeC", false)
		gwRoute, _ := c.getState("gwRoute", false)
		c.assocRoute(edgeC[0], gwRoute[0])
		return nil
	})
	run.AddNode("assocRouteEdgeC", assocRouteEdgeC)
	run.AddEdge("edgeCSubnet", "assocRouteEdgeC")
	run.AddEdge("createRoute", "assocRouteEdgeC")

	edgeSgFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		edgeSg := c.securityGroup(vpc[0], "edge", "Edge Bastion")
		if edgeSg == "" {
			return errors.New("failed to create edge security group")
		}
		_ = c.saveState("edgeSg", []string{edgeSg}, false)
		return nil
	})
	run.AddNode("edgeSg", edgeSgFn)
	run.AddEdge("vpc", "edgeSg")
	masterSgFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		masterSg := c.securityGroup(vpc[0], "master", "Master Nodes")
		if masterSg == "" {
			return errors.New("failed to create master security group")
		}
		_ = c.saveState("masterSg", []string{masterSg}, false)
		return nil
	})
	run.AddNode("masterSg", masterSgFn)
	run.AddEdge("vpc", "masterSg")
	masterLBSgFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		masterLBSg := c.securityGroup(vpc[0], "master-lb", "Master Load Balancer")
		if masterLBSg == "" {
			return errors.New("failed to create master load balancer security group")
		}
		_ = c.saveState("masterLBSg", []string{masterLBSg}, false)
		return nil
	})
	run.AddNode("masterLBSg", masterLBSgFn)
	run.AddEdge("vpc", "masterLBSg")
	nodeSgFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		nodeSg := c.securityGroup(vpc[0], "node", "Worker Nodes")
		if nodeSg == "" {
			return errors.New("failed to create node security group")
		}
		_ = c.saveState("nodeSg", []string{nodeSg}, false)
		return nil
	})
	run.AddNode("nodeSg", nodeSgFn)
	run.AddEdge("vpc", "nodeSg")

	edgeSgRulesFn := rund.NewFuncOperator(func() error {
		edgeSg, _ := c.getState("edgeSg", false)
		masterSg, _ := c.getState("masterSg", false)
		nodeSg, _ := c.getState("nodeSg", false)
		// edgeEgress := c.securityGroupRule(0, 0, "0.0.0.0/0", "-1", "egress")
		edgeIngress := []ec2.IpPermission{}
		edgeIngress = append(edgeIngress, c.securityGroupRule(22, 22, "0.0.0.0/0", "tcp", "ssh provisioning"))
		edgeIngress = append(edgeIngress, c.securityGroupRule(22223, 22223, "0.0.0.0/0", "tcp", "ssh pivot"))
		edgeIngress = append(edgeIngress, c.securityGroupRule(500, 500, "0.0.0.0/0", "udp", "500 IpSec"))
		edgeIngress = append(edgeIngress, c.securityGroupRule(4500, 4500, "0.0.0.0/0", "udp", "4500 IpSec"))
		edgeIngress = append(edgeIngress, c.securityGroupRule(443, 443, "0.0.0.0/0", "tcp", "https just in case"))
		edgeIngress = append(edgeIngress, c.securityGroupRule(0, 65535, masterSg[0], "-1", "NAT Master security group"))
		edgeIngress = append(edgeIngress, c.securityGroupRule(0, 65535, nodeSg[0], "-1", "NAT Node security group"))
		c.securityGroupRuleApply(edgeSg[0], edgeIngress, Ingress)
		return nil
	})
	run.AddNode("edgeSgRules", edgeSgRulesFn)
	run.AddEdge("nodeSg", "edgeSgRules")
	run.AddEdge("masterSg", "edgeSgRules")
	run.AddEdge("edgeSg", "edgeSgRules")

	masterSgRulesFn := rund.NewFuncOperator(func() error {
		edgeSg, _ := c.getState("edgeSg", false)
		masterSg, _ := c.getState("masterSg", false)
		masterLBSg, _ := c.getState("masterLBSg", false)
		nodeSg, _ := c.getState("nodeSg", false)
		masterIngress := []ec2.IpPermission{}
		masterIngress = append(masterIngress, c.securityGroupRule(6443, 6443, podCidr.String(), "tcp", "Allow pods to get API info"))
		masterIngress = append(masterIngress, c.securityGroupRule(443, 443, podCidr.String(), "tcp", "Allow pods to get API info"))
		masterIngress = append(masterIngress, c.securityGroupRule(53, 53, podCidr.String(), "udp", "Allow pods to get DNS"))
		masterIngress = append(masterIngress, c.securityGroupRule(22, 22, edgeSg[0], "tcp", "ssh provisioning"))
		masterIngress = append(masterIngress, c.securityGroupRule(443, 443, nodeSg[0], "tcp", "Allow nodes to API"))
		masterIngress = append(masterIngress, c.securityGroupRule(0, 65535, masterSg[0], "-1", "master master communication"))
		masterIngress = append(masterIngress, c.securityGroupRule(6443, 6443, masterLBSg[0], "tcp", "master-lb master communication"))
		c.securityGroupRuleApply(masterSg[0], masterIngress, Ingress)
		return nil
	})
	run.AddNode("masterSgRules", masterSgRulesFn)
	run.AddEdge("nodeSg", "masterSgRules")
	run.AddEdge("masterSg", "masterSgRules")
	run.AddEdge("edgeSg", "masterSgRules")
	run.AddEdge("masterLBSg", "masterSgRules")

	masterLBSgRulesFn := rund.NewFuncOperator(func() error {
		edgeSg, _ := c.getState("edgeSg", false)
		masterSg, _ := c.getState("masterSg", false)
		masterLBSg, _ := c.getState("masterLBSg", false)
		nodeSg, _ := c.getState("nodeSg", false)
		masterLbIngress := []ec2.IpPermission{}
		masterLbIngress = append(masterLbIngress, c.securityGroupRule(6443, 6443, edgeSg[0], "tcp", "VPN Users to get kubectl"))
		masterLbIngress = append(masterLbIngress, c.securityGroupRule(6443, 6443, nodeSg[0], "tcp", "Nodes to API"))
		masterLbIngress = append(masterLbIngress, c.securityGroupRule(6443, 6443, masterSg[0], "tcp", "Nodes to API"))
		c.securityGroupRuleApply(masterLBSg[0], masterLbIngress, Ingress)
		return nil
	})
	run.AddNode("masterLBSgRules", masterLBSgRulesFn)
	run.AddEdge("nodeSg", "masterLBSgRules")
	run.AddEdge("masterSg", "masterLBSgRules")
	run.AddEdge("edgeSg", "masterLBSgRules")
	run.AddEdge("masterLBSg", "masterLBSgRules")

	nodeSgRulesFn := rund.NewFuncOperator(func() error {
		edgeSg, _ := c.getState("edgeSg", false)
		masterSg, _ := c.getState("masterSg", false)
		// masterLBSg, _ := c.getState("masterLBSg", false)
		nodeSg, _ := c.getState("nodeSg", false)
		nodeIngress := []ec2.IpPermission{}
		nodeIngress = append(nodeIngress, c.securityGroupRule(10250, 10250, masterSg[0], "tcp", "master to kubelet"))
		nodeIngress = append(nodeIngress, c.securityGroupRule(1024, 65535, masterSg[0], "tcp", "Pod Comunication"))
		nodeIngress = append(nodeIngress, c.securityGroupRule(0, 65535, nodeSg[0], "-1", "node to node"))
		nodeIngress = append(nodeIngress, c.securityGroupRule(22, 22, edgeSg[0], "tcp", "edge ssh"))
		c.securityGroupRuleApply(nodeSg[0], nodeIngress, Ingress)
		return nil
	})
	run.AddNode("nodeSgRules", nodeSgRulesFn)
	run.AddEdge("nodeSg", "nodeSgRules")
	run.AddEdge("masterSg", "nodeSgRules")
	run.AddEdge("edgeSg", "nodeSgRules")

	// @TODO Move to Edge Nodes with Cilium XDP Load Balancing
	amiFwFn := rund.NewFuncOperator(func() error {
		ami, _, _, err := c.SearchAMI("538276064493", map[string]string{
			"name":"alpine-ami-"+hyperctl.AlpineVersion+"*",
			"architecture":"x86_64",
		})
		if err != nil {
			return err
		}
		_ = c.saveState("amiFw", []string{ami}, false)
		return nil
	})
	run.AddNode("amiFw", amiFwFn)

	fwAFn := rund.NewFuncOperator(func() error {
		bastionKey, _ := c.getState("bastionKey", false)
		edgeA, _      := c.getState("edgeA", false)
		edgeSg, _     := c.getState("edgeSg", false)
		ami, _        := c.getState("amiFw", false)
		fwA, err := c.instance(&Instance{
			name: "Firewall - 1",
			ami: ami[0],
			key: bastionKey[0],
			subnet: edgeA[0],
			sg: edgeSg[0],
			nat: true})
		if err != nil {
			log.Errorf("failed to create fireware instance, %v", err)
			return err
		}
		_ = c.saveState("fwA", []string{fwA.id, fwA.public}, false)
		return nil
	})
	run.AddNode("fwA", fwAFn)
	run.AddEdge("edgeASubnet", "fwA")
	run.AddEdge("ssh-keys", "fwA")
	run.AddEdge("edgeSg", "fwA")
	run.AddEdge("amiFw", "fwA")

	natRouteFn := rund.NewFuncOperator(func() error {
		vpc, _ := c.getState("vpc", false)
		fwA, _ := c.getState("fwA", false)
		natRoute := c.routeTable(vpc[0], fwA[0], "0.0.0.0/0")
		if natRoute == "" {
			return errors.New("failed to create nat route")
		}
		_ = c.saveState("natRoute", []string{natRoute}, false)
		return nil
	})
	run.AddNode("natRoute", natRouteFn)
	run.AddEdge("fwA", "natRoute")

	assocRouteMasterA := rund.NewFuncOperator(func() error {
		masterA, _ := c.getState("masterA", false)
		natRoute, _ := c.getState("natRoute", false)
		c.assocRoute(masterA[0], natRoute[0])
		return nil
	})
	run.AddNode("assocRouteMasterA", assocRouteMasterA)
	run.AddEdge("natRoute", "assocRouteMasterA")
	run.AddEdge("masterASubnet", "assocRouteMasterA")
	assocRouteMasterB := rund.NewFuncOperator(func() error {
		masterB, _ := c.getState("masterB", false)
		natRoute, _ := c.getState("natRoute", false)
		c.assocRoute(masterB[0], natRoute[0])
		return nil
	})
	run.AddNode("assocRouteMasterB", assocRouteMasterB)
	run.AddEdge("natRoute", "assocRouteMasterB")
	run.AddEdge("masterASubnet", "assocRouteMasterB")
	assocRouteMasterC := rund.NewFuncOperator(func() error {
		masterC, _ := c.getState("masterC", false)
		natRoute, _ := c.getState("natRoute", false)
		c.assocRoute(masterC[0], natRoute[0])
		return nil
	})
	run.AddNode("assocRouteMasterC", assocRouteMasterC)
	run.AddEdge("natRoute", "assocRouteMasterC")
	run.AddEdge("masterCSubnet", "assocRouteMasterC")
	assocRouteNodeA := rund.NewFuncOperator(func() error {
		nodeA, _ := c.getState("nodeA", false)
		natRoute, _ := c.getState("natRoute", false)
		c.assocRoute(nodeA[0], natRoute[0])
		return nil
	})
	run.AddNode("assocRouteNodeA", assocRouteNodeA)
	run.AddEdge("natRoute", "assocRouteNodeA")
	run.AddEdge("nodeASubnet", "assocRouteNodeA")
	assocRouteNodeB := rund.NewFuncOperator(func() error {
		nodeB, _ := c.getState("nodeB", false)
		natRoute, _ := c.getState("natRoute", false)
		c.assocRoute(nodeB[0], natRoute[0])
		return nil
	})
	run.AddNode("assocRouteNodeB", assocRouteNodeB)
	run.AddEdge("natRoute", "assocRouteNodeB")
	run.AddEdge("nodeBSubnet", "assocRouteNodeB")
	assocRouteNodeC := rund.NewFuncOperator(func() error {
		nodeC, _ := c.getState("nodeC", false)
		natRoute, _ := c.getState("natRoute", false)
		c.assocRoute(nodeC[0], natRoute[0])
		return nil
	})
	run.AddNode("assocRouteNodeC", assocRouteNodeC)
	run.AddEdge("natRoute", "assocRouteNodeC")
	run.AddEdge("nodeCSubnet", "assocRouteNodeC")

	provisionFwA := rund.NewFuncOperator(func() error {
		fwA, _ := c.getState("fwA", false)
		fwHostA := bastion.New(fwA[1] + "/32" , 22, key.PrivateKey, "alpine")
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
			return err
		}
		return nil
	})
	run.AddNode("provisionFwA", provisionFwA)
	run.AddEdge("fwA", "provisionFwA")

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
	masterRole := rund.NewFuncOperator(func() error {
		if _, err := c.CreateRole("master-"+c.Id, r); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("masterRole", masterRole)
	run.AddEdge("table", "masterRole")
	nodeRole := rund.NewFuncOperator(func() error {
		_, err = c.CreateRole("node-"+c.Id, r)
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("nodeRole", nodeRole)
	run.AddEdge("table", "nodeRole")

	masterGeneralPolicy := rund.NewFuncOperator(func() error {
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
			return err
		}
		return c.saveState("masterGeneralPolicy", []string{masterPolicy}, true)
	})
	run.AddNode("masterGeneralPolicy", masterGeneralPolicy)
	run.AddEdge("table", "masterGeneralPolicy")

	attachMasterPolicy := rund.NewFuncOperator(func() error {
		masterPolicy, _ := c.getState("masterGeneralPolicy", false)
		err = c.AttachPolicy("master-"+c.Id, masterPolicy[0])
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachMasterPolicy", attachMasterPolicy)
	run.AddEdge("masterGeneralPolicy", "attachMasterPolicy")
	run.AddEdge("masterRole", "attachMasterPolicy")

	nodeGeneralPolicy := rund.NewFuncOperator(func() error {
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
			return err
		}
		return c.saveState("nodeGeneralPolicy", []string{nodePolicy}, true)
	})
	run.AddNode("nodeGeneralPolicy", nodeGeneralPolicy)
	run.AddEdge("table", "nodeGeneralPolicy")

	attachNodePolicy := rund.NewFuncOperator(func() error {
		nodePolicy, _ := c.getState("nodeGeneralPolicy", false)
		err = c.AttachPolicy("node-"+c.Id, nodePolicy[0])
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachNodePolicy", attachNodePolicy)
	run.AddEdge("nodeGeneralPolicy", "attachNodePolicy")
	run.AddEdge("nodeRole", "attachNodePolicy")

	attachMasterCNIPolicy := rund.NewFuncOperator(func() error {
		err = c.AttachPolicy("master-"+c.Id, "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy")
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachMasterCNIPolicy", attachMasterCNIPolicy)
	run.AddEdge("masterRole", "attachMasterCNIPolicy")
	attachMasterWorkerPolicy := rund.NewFuncOperator(func() error {
		err = c.AttachPolicy("master-"+c.Id, "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy")
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachMasterWorkerPolicy", attachMasterWorkerPolicy)
	run.AddEdge("masterRole", "attachMasterWorkerPolicy")
	attachMasterVPCPolicy := rund.NewFuncOperator(func() error {
		err = c.AttachPolicy("master-"+c.Id, "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController")
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachMasterVPCPolicy", attachMasterVPCPolicy)
	run.AddEdge("masterRole", "attachMasterVPCPolicy")
	attachNodeCNIPolicy := rund.NewFuncOperator(func() error {
		err = c.AttachPolicy("node-"+c.Id, "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy")
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachNodeCNIPolicy", attachNodeCNIPolicy)
	run.AddEdge("nodeRole", "attachNodeCNIPolicy")
	attachNodeWorkerPolicy := rund.NewFuncOperator(func() error {
		err = c.AttachPolicy("node-"+c.Id, "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy")
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachNodeWorkerPolicy", attachNodeWorkerPolicy)
	run.AddEdge("nodeRole", "attachNodeWorkerPolicy")
	attachNodeVPCPolicy := rund.NewFuncOperator(func() error {
		err = c.AttachPolicy("node-"+c.Id, "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController")
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachNodeVPCPolicy", attachNodeVPCPolicy)
	run.AddEdge("nodeRole", "attachNodeVPCPolicy")

	masterInstanceProfile := rund.NewFuncOperator(func() error {
		masterProfile, err := c.instanceProfile("master-"+c.Id)
		if err != nil {
			return err
		}
		_ = c.saveState("masterProfile", []string{masterProfile}, false)
		return nil
	})
	run.AddNode("masterInstanceProfile", masterInstanceProfile)
	run.AddEdge("masterRole", "masterInstanceProfile")
	nodeInstanceProfile := rund.NewFuncOperator(func() error {
		nodeProfile, err := c.instanceProfile("node-"+c.Id)
		if err != nil {
			return err
		}
		_ = c.saveState("nodeProfile", []string{nodeProfile}, false)
		return nil
	})
	run.AddNode("nodeInstanceProfile", nodeInstanceProfile)
	run.AddEdge("nodeRole", "nodeInstanceProfile")
	masterRoleInstanceProfile := rund.NewFuncOperator(func() error {
		err = c.addRoleInstance("master-"+c.Id, "master-"+c.Id)
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("masterRoleInstanceProfile", masterRoleInstanceProfile)
	run.AddEdge("masterInstanceProfile", "masterRoleInstanceProfile")
	nodeRoleInstanceProfile := rund.NewFuncOperator(func() error {
		err = c.addRoleInstance("node-"+c.Id, "node-"+c.Id)
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("nodeRoleInstanceProfile", nodeRoleInstanceProfile)
	run.AddEdge("masterRole", "nodeRoleInstanceProfile")

	amiFn := rund.NewFuncOperator(func() error {
		ami, _, _, err := c.SearchAMI("751883444564", map[string]string{"name":"hyperspike-*"})
		if err != nil {
			return err
		}
		_ = c.saveState("ami", []string{ami}, false)
		return nil
	})
	run.AddNode("ami", amiFn)

	masterTemplateFn := rund.NewFuncOperator(func() error {
		log.Info("creating master launch template")
		ami, _ := c.getState("ami", false)
		bastionKey, _ := c.getState("bastionKey", false)
		masterSg, _ := c.getState("masterSg", false)
		masterProfile, _ := c.getState("masterProfile", false)
		_, err = c.createLaunchTemplate("master-"+c.Id, "t3a.medium", ami[0], masterProfile[0], bastionKey[0], masterSg[0], `#!/bin/sh
sudo hyperctl boot`)
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("masterTemplate", masterTemplateFn)
	run.AddEdge("ami", "masterTemplate")
	run.AddEdge("ssh-keys", "masterTemplate")
	run.AddEdge("masterSg", "masterTemplate")
	run.AddEdge("masterRoleInstanceProfile", "masterTemplate")

	nodeTemplateFn := rund.NewFuncOperator(func() error {
		log.Info("creating node launch template")
		ami, _ := c.getState("ami", false)
		bastionKey, _ := c.getState("bastionKey", false)
		nodeSg, _ := c.getState("nodeSg", false)
		nodeProfile, _ := c.getState("nodeProfile", false)
		_, err = c.createLaunchTemplate("node-"+c.Id, "t3a.medium", ami[0], nodeProfile[0], bastionKey[0], nodeSg[0], `#!/bin/sh
sudo hyperctl boot`)
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("nodeTemplate", nodeTemplateFn)
	run.AddEdge("ami", "nodeTemplate")
	run.AddEdge("ssh-keys", "nodeTemplate")
	run.AddEdge("nodeSg", "nodeTemplate")
	run.AddEdge("nodeRoleInstanceProfile", "nodeTemplate")

	createLBFn := rund.NewFuncOperator(func() error {
		masterA, _ := c.getState("masterA", false)
		masterB, _ := c.getState("masterB", false)
		masterC, _ := c.getState("masterC", false)
		masterLbSg, _ := c.getState("masterLBSg", false)
		log.Info("creating master load balancer")
		c.master.Endpoint, err = c.loadBalancer("master-lb-"+c.Id, masterLbSg[0], []string{masterA[0], masterB[0], masterC[0]})
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createLB", createLBFn)
	run.AddEdge("masterLBSg", "createLB")
	run.AddEdge("masterASubnet", "createLB")
	run.AddEdge("masterBSubnet", "createLB")
	run.AddEdge("masterCSubnet", "createLB")

	irsaBucketFn := rund.NewFuncOperator(func() error {
		log.Info("creating IRSA OIDC s3 bucket")
		irsaBucket, err := c.bucket(c.Id+"-irsa")
		if err != nil {
			return err
		}
		c.master.Bucket = irsaBucket
		return c.saveState("irsaBucket", []string{irsaBucket}, true)
	})
	run.AddNode("irsaBucket", irsaBucketFn)
	run.AddEdge("table", "irsaBucket")

	oidcIAMFn := rund.NewFuncOperator(func() error {
		_, err = c.oidcIAM("https://s3."+c.Region+".amazonaws.com/"+c.Id+"-irsa/")
		return err
	})
	run.AddNode("oidcIAM", oidcIAMFn)
	run.AddEdge("table", "oidcIAM")

	irsaPolicyFn := rund.NewFuncOperator(func() error {
		irsaBucket, _ := c.getState("irsaBucket", false)
		irsaPolicy, err := c.IRSAPolicy(irsaBucket[0])
		if err != nil {
			return err
		}
		return c.saveState("irsaPolicy", []string{irsaPolicy}, true)
	})
	run.AddNode("irsaPolicy", irsaPolicyFn)
	run.AddEdge("irsaBucket", "irsaPolicy")
	irsaAttachPolicy := rund.NewFuncOperator(func() error {
		irsaPolicy, _ := c.getState("irsaPolicy", false)
		return  c.AttachPolicy("master-"+c.Id, irsaPolicy[0])
	})
	run.AddNode("irsaAttachPolicy", irsaAttachPolicy)
	run.AddEdge("irsaPolicy", "irsaAttachPolicy")
	run.AddEdge("masterRole", "irsaAttachPolicy")

	keyFn := rund.NewFuncOperator(func() error {
		var kmsKey string
		kmsKey, c.master.KeyARN, err = c.kms(c.Id)
		if err != nil {
			return err
		}
		return c.saveState("kms", []string{kmsKey}, true)
	})
	run.AddNode("key", keyFn)
	run.AddEdge("table", "key")

	keyPolicy := rund.NewFuncOperator(func() error {
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
			return err
		}
		return c.saveState("ebsPolicy", []string{ebsEncryptPolicy}, true)
	})
	run.AddNode("keyPolicy", keyPolicy)
	run.AddEdge("key", "keyPolicy")

	attachKeyMaster := rund.NewFuncOperator(func() error {
		ebsEncryptPolicy, _ := c.getState("ebsPolicy", false)
		return c.AttachPolicy("master-"+c.Id, ebsEncryptPolicy[0])
	})
	run.AddNode("attachKeyMaster", attachKeyMaster)
	run.AddEdge("keyPolicy", "attachKeyMaster")
	run.AddEdge("masterRole", "attachKeyMaster")

	nodeSecret := rund.NewFuncOperator(func() error {
		kmsKey, _ := c.getState("kms", false)
		secretId, err := c.secret(c.Id, kmsKey[0], "{}")
		c.master.TokenLocation = secretId
		if err != nil {
			return err
		}
		return c.saveState("nodeSecret", []string{secretId}, false)
	})
	run.AddNode("nodeSecret", nodeSecret)
	run.AddEdge("key", "nodeSecret")

	adminSecret := rund.NewFuncOperator(func() error {
		kmsKey, _ := c.getState("kms", false)
		secretAdminId, err := c.secret(c.Id+"-admin", kmsKey[0], "{}")
		if err != nil {
			return err
		}
		return c.saveState("adminSecret", []string{secretAdminId}, false)
	})
	run.AddNode("adminSecret", adminSecret)
	run.AddEdge("key", "adminSecret")

	secretReadPolicyFn := rund.NewFuncOperator(func() error {
		secretId, _ := c.getState("nodeSecret", false)
		secretReadP := policy{
			Statement: []statement{
				{
					Action: []string{
						"secretsmanager:GetSecretValue",
						"secretsmanager:DescribeSecret",
						"secretsmanager:ListSecretVersionIds",
					},
					Resource: []string{
						secretId[0],
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
			return err
		}
		return c.saveState("secretReadPolicy", []string{secretReadPolicy}, true)
	})
	run.AddNode("secretReadPolicy", secretReadPolicyFn)
	run.AddEdge("nodeSecret", "secretReadPolicy")
	attachSecretNodePolicyFn := rund.NewFuncOperator(func() error {
		secretReadPolicy, _ := c.getState("secretReadPolicy", false)
		return c.AttachPolicy("node-"+c.Id, secretReadPolicy[0])
	})
	run.AddNode("attachSecretNodePolicy", attachSecretNodePolicyFn)
	run.AddEdge("secretReadPolicy", "attachSecretNodePolicy")
	run.AddEdge("nodeRole", "attachSecretNodePolicy")
	attachSecretMasterPolicyFn := rund.NewFuncOperator(func() error {
		secretReadPolicy, _ := c.getState("secretReadPolicy", false)
		return c.AttachPolicy("master-"+c.Id, secretReadPolicy[0])
	})
	run.AddNode("attachSecretMasterPolicy", attachSecretMasterPolicyFn)
	run.AddEdge("secretReadPolicy", "attachSecretMasterPolicy")
	run.AddEdge("masterRole", "attachSecretMasterPolicy")

	secretWritePolicyFn := rund.NewFuncOperator(func() error {
		secretId, _ := c.getState("nodeSecret", false)
		secretAdminId, _ := c.getState("adminSecret", false)
		secretWriteP := policy{
			Statement: []statement{
				{
					Action: []string{
						"secretsmanager:PutSecretValue",
						"secretsmanager:UpdateSecret",
					},
					Resource: []string{
						secretId[0],
						secretAdminId[0],
					},
					Effect: "Allow",
				},
			},
		}
		secretWritePolicy, err := c.CreatePolicy("secret-write-"+c.Id, secretWriteP)
		if err != nil {
			return err
		}
		return c.saveState("secretWritePolicy",[]string{secretWritePolicy}, true)
	})
	run.AddNode("secretWritePolicy", secretWritePolicyFn)
	run.AddEdge("nodeSecret", "secretWritePolicy")
	run.AddEdge("adminSecret", "secretWritePolicy")

	attachSecretWritePolicyFn := rund.NewFuncOperator(func() error {
		secretWritePolicy, _ := c.getState("secretWritePolicy", false)
		return c.AttachPolicy("master-"+c.Id, secretWritePolicy[0])
	})
	run.AddNode("attachSecretWritePolicy", attachSecretWritePolicyFn)
	run.AddEdge("secretWritePolicy", "attachSecretWritePolicy")
	run.AddEdge("masterRole", "attachSecretWritePolicy")

	createTableFn := rund.NewFuncOperator(func() error {
		table, err := c.createLocalTable(c.Id)
		if err != nil {
			return err
		}
		return c.saveState("table", []string{table}, true)
	})
	run.AddNode("table", createTableFn)

	createGlobalTable := rund.NewFuncOperator(func() error {
		if err := c.isTable("hyperspike") ; err != nil {
			_, err := c.globalDB([]string{c.Region, "us-east-2", "us-west-2"})
			return err
		}
		return nil
	})
	run.AddNode("globalTable", createGlobalTable)

	tableReadPolicyFn := rund.NewFuncOperator(func() error {
		table, _ := c.getState("table", false)
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
						table[0],
						table[0]+"/index/*",
					},
					Effect: "Allow",
				},
			},
		}
		tableReadPolicy, err := c.CreatePolicy("dynamo-read-"+c.Id, tableReadP)
		if err != nil {
			return err
		}
		return c.saveState("tableReadPolicy", []string{tableReadPolicy}, true)
	})
	run.AddNode("tableReadPolicy", tableReadPolicyFn)
	run.AddEdge("table", "tableReadPolicy")

	attachTableReadMaster := rund.NewFuncOperator(func() error {
		tableReadPolicy, _ := c.getState("tableReadPolicy", false)
		if err = c.AttachPolicy("master-"+c.Id, tableReadPolicy[0]); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachTableReadMaster", attachTableReadMaster)
	run.AddEdge("tableReadPolicy", "attachTableReadMaster")
	run.AddEdge("masterRole", "attachTableReadMaster")
	attachTableReadNode := rund.NewFuncOperator(func() error {
		tableReadPolicy, _ := c.getState("tableReadPolicy", false)
		if err := c.AttachPolicy("node-"+c.Id, tableReadPolicy[0]); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachTableReadNode", attachTableReadNode)
	run.AddEdge("tableReadPolicy", "attachTableReadNode")
	run.AddEdge("nodeRole", "attachTableReadNode")

	tableWritePolicyFn := rund.NewFuncOperator(func() error {
		table, _ := c.getState("table", false)
		tableWriteP := policy{
			Statement: []statement{
				{
					Action: []string{
						"dynamodb:PutItem",
						"dynamodb:UpdateItem",
						"dynamodb:DeleteItem",
					},
					Resource: []string{
						table[0],
						table[0]+"/index/*",
					},
					Effect: "Allow",
				},
			},
		}
		tableWritePolicy, err := c.CreatePolicy("dynamo-write-"+c.Id, tableWriteP)
		if err != nil {
			return err
		}
		return c.saveState("tableWritePolicy", []string{tableWritePolicy}, true)
	})
	run.AddNode("tableWritePolicy", tableWritePolicyFn)
	run.AddEdge("table", "tableWritePolicy")
	run.AddEdge("masterRole", "tableWritePolicy")

	attachTableWriteMaster := rund.NewFuncOperator(func() error {
		tableWritePolicy, _ := c.getState("tableWritePolicy", false)
		if err := c.AttachPolicy("master-"+c.Id, tableWritePolicy[0]); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("attachTableWriteMaster", attachTableWriteMaster)
	run.AddEdge("tableWritePolicy", "attachTableWriteMaster")

	uploadMeta := rund.NewFuncOperator(func() error {
		c.agentStore = dynalock.New(dynamodb.New(c.Cfg), c.Id, "Agent")
		return c.uploadClusterMeta(c.master)
	})
	run.AddNode("uploadMeta", uploadMeta)
	run.AddEdge("table", "uploadMeta")

	createMasterAAsg := rund.NewFuncOperator(func() error {
		masterA, _ := c.getState("masterA", false)
		err = c.createASG("master-"+c.Id+"-a", "master-"+c.Id, masterA[0], "master-lb-"+c.Id, 1, 1, 1, map[string]string{
			"Name": "Master - "+c.Id+" - A",
			"KubernetesCluster": c.Id,
			strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
			"kubernetes.io/role/master": "1",
		})
		if err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createMasterAAsg", createMasterAAsg)
	run.AddEdge("createLB", "createMasterAAsg")
	run.AddEdge("masterTemplate", "createMasterAAsg")
	createMasterBAsg := rund.NewFuncOperator(func() error {
		masterB, _ := c.getState("masterB", false)
		if err := c.createASG("master-"+c.Id+"-b", "master-"+c.Id, masterB[0], "master-lb-"+c.Id, 1, 1, 1, map[string]string{
			"Name": "Master - "+c.Id+" - B",
			"KubernetesCluster": c.Id,
			strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
			"kubernetes.io/role/master": "1",
		}); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createMasterBAsg", createMasterBAsg)
	run.AddEdge("createLB", "createMasterBAsg")
	run.AddEdge("masterTemplate", "createMasterBAsg")
	createMasterCAsg := rund.NewFuncOperator(func() error {
		masterC, _ := c.getState("masterC", false)
		if err := c.createASG("master-"+c.Id+"-c", "master-"+c.Id, masterC[0], "master-lb-"+c.Id, 1, 1, 1, map[string]string{
			"Name": "Master - "+c.Id+" - C",
			"KubernetesCluster": c.Id,
			strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
			"kubernetes.io/role/master": "1",
		}); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createMasterCAsg", createMasterCAsg)
	run.AddEdge("createLB", "createMasterCAsg")
	run.AddEdge("masterTemplate", "createMasterCAsg")

	createNodeAAsg := rund.NewFuncOperator(func() error {
		nodeA, _ := c.getState("nodeA", false)
		if err := c.createASG("node-"+c.Id+"-a", "node-"+c.Id, nodeA[0], "", 1, 1, 1, map[string]string{
			"Name": "Node - "+c.Id+" - A",
			"KubernetesCluster": c.Id,
			strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
			"kubernetes.io/role/node": "1",
		}); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createNodeAAsg", createNodeAAsg)
	run.AddEdge("nodeASubnet", "createNodeAAsg")
	run.AddEdge("nodeTemplate", "createNodeAAsg")
	createNodeBAsg := rund.NewFuncOperator(func() error {
		nodeB, _ := c.getState("nodeB", false)
		if err := c.createASG("node-"+c.Id+"-b", "node-"+c.Id, nodeB[0], "", 1, 1, 1, map[string]string{
			"Name": "Node - "+c.Id+" - B",
			"KubernetesCluster": c.Id,
			strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
			"kubernetes.io/role/node": "1",
		}); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createNodeBAsg", createNodeBAsg)
	run.AddEdge("nodeBSubnet", "createNodeBAsg")
	run.AddEdge("nodeTemplate", "createNodeBAsg")
	createNodeCAsg := rund.NewFuncOperator(func() error {
		nodeC, _ := c.getState("nodeC", false)
		if err := c.createASG("node-"+c.Id+"-c", "node-"+c.Id, nodeC[0], "", 1, 1, 1, map[string]string{
			"Name": "Node - "+c.Id+" - C",
			"KubernetesCluster": c.Id,
			strings.Join([]string{"kubernetes.io/cluster/", c.Id}, ""): "owned",
			"kubernetes.io/role/node": "1",
		}); err != nil {
			return err
		}
		return nil
	})
	run.AddNode("createNodeCAsg", createNodeCAsg)
	run.AddEdge("nodeCSubnet", "createNodeCAsg")
	run.AddEdge("nodeTemplate", "createNodeCAsg")

	err = run.Run()
	if err != nil {
		log.Errorf("failed to deploy on graph traversal: %v", err)
		return
	}
}

// save state to the global state struct, and optionally commit remotely
func (c *Client) saveState(key string, values []string, remote bool) error {
	c.state[key] = values
	if remote {
		if c.agentStore == nil {
			c.agentStore = dynalock.New(dynamodb.New(c.Cfg), c.Id, "Agent")
		}
		b, err := json.Marshal(values)
		if err != nil {
			log.Errorf("state key: %s, failed to encode value to json, %v", key, err)
			return err
		}
		err = c.agentStore.Put(context.Background(), "state-"+key, dynalock.WriteWithAttributeValue(&dynamodb.AttributeValue{S: aws.String(string(b))}), dynalock.WriteWithNoExpires())
		log.Errorf("failed to save remote state %s, %v", key, err)
		return err
	}
	return nil
}

// get state from the global state struct, and optionally fetch remotely
func (c *Client) getState(key string, remote bool) ([]string, error) {
	if remote {
		if c.agentStore == nil {
			c.agentStore = dynalock.New(dynamodb.New(c.Cfg), c.Id, "Agent")
		}
		ret, err := c.agentStore.Get(context.Background(), "state-"+key)
		if err != nil {
			log.Errorf("failed to get remote state %s, %v", key, err)
			return []string{}, err
		}
		v := []string{}
		err = json.Unmarshal([]byte(*(ret.AttributeValue().S)), &v)
		if err != nil {
			log.Errorf("state key: %s, failed to decode json to string, %v", key, err)
			return []string{}, err
		}
		c.state[key] = v
		return v, nil
	}
	return c.state[key], nil
}

func (c *Client) isTable(name string) error {
	svc := dynamodb.New(c.Cfg)
	reqS := svc.DescribeTableRequest(&dynamodb.DescribeTableInput{
			TableName: aws.String(name),
		})
	count := 0
	limit := 3
	for {
		resS, err := reqS.Send(context.Background())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case dynamodb.ErrCodeResourceNotFoundException:
					log.Error(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
					return err
				case dynamodb.ErrCodeInternalServerError:
					log.Error(dynamodb.ErrCodeInternalServerError, aerr.Error())
				default:
					log.Error(aerr.Error())
				}
			} else {
				log.Error(err.Error())
			}
			return err
		}
		status := resS.DescribeTableOutput.Table.TableStatus
		if status == dynamodb.TableStatusActive {
			log.Debugf("table %s, ready and found", name)
			break
		}
		time.Sleep(500 * time.Millisecond)
		count++
		if count >= limit {
			return err
		}
	}

	return nil
}

func (c *Client) globalDB(regions []string) (string, error) {

	globalTable, err := c.createTable("hyperspike", true, regions)
	if err != nil {
		return "", err
	}

	return globalTable, nil
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
func (c Client) azs() ([]string, error) {

	svc := ec2.New(c.Cfg)
	input := &ec2.DescribeAvailabilityZonesInput{
		Filters: []ec2.Filter{
			{
				Name: aws.String("region-name"),
				Values: []string{
					c.Region,
				},
			},
		},
	}
	req := svc.DescribeAvailabilityZonesRequest(input)
	res, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return []string{}, err
	}
	var ret []string
	for _, az := range res.AvailabilityZones {
		ret = append(ret, *az.ZoneId)
	}

	return ret, nil
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
				Key:   aws.String("kubernetesCluster"),
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

func (c Client) key(name string, s *ssh.Ssh) string {
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

	hcInput := &elasticloadbalancing.ConfigureHealthCheckInput{
		HealthCheck: &elasticloadbalancing.HealthCheck{
			HealthyThreshold:   aws.Int64(2),
			Interval:           aws.Int64(10),
			Target:             aws.String("HTTPS:6443/healthz"),
			Timeout:            aws.Int64(5),
			UnhealthyThreshold: aws.Int64(2),
		},
		LoadBalancerName: aws.String(name),
	}

	hcReq := svc.ConfigureHealthCheckRequest(hcInput)
	_, err = hcReq.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case elasticloadbalancing.ErrCodeAccessPointNotFoundException:
				log.Println(elasticloadbalancing.ErrCodeAccessPointNotFoundException, aerr.Error())
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

func (c Client) uploadString(bucket, path, body string) error {
	svc := s3.New(c.Cfg)
	in := &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(path),
		ACL:    s3.ObjectCannedACLPublicRead,
		Body:   bytes.NewReader([]byte(body)),
		ContentType: aws.String("application/json"),
	}
	req := svc.PutObjectRequest(in)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
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

func (c Client) createLocalTable(name string) (string, error) {
	return c.createTable(name, false, []string{})
}

func (c Client) createTable(name string, global bool, regions []string) (string, error) {
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
	if global {
		input.StreamSpecification = &dynamodb.StreamSpecification{
			StreamEnabled: aws.Bool(true),
			StreamViewType: dynamodb.StreamViewTypeNewAndOldImages,
		}
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
	log.Infof("table %s, created", name)
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
	if global {
		replicate := &dynamodb.UpdateTableInput{}
		for _, region := range regions {
			if region != c.Region {
				replicate.ReplicaUpdates = append(replicate.ReplicaUpdates, dynamodb.ReplicationGroupUpdate{
					Create: &dynamodb.CreateReplicationGroupMemberAction{
						RegionName: aws.String(region),
					},
				})
			}
		}
		reqRep := svc.UpdateTableRequest(replicate)
		if _, err = reqRep.Send(context.Background()); err != nil {
			log.Errorf("failed to replicate global table, %v", err)
			return "", err
		}
	}
	// log.Println(res)
	return *result.TableDescription.TableArn, nil
}

func getCert(address string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: false,
		MinVersion: tls.VersionTLS12,
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
	// #nosec
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
