package aws

import (
	"context"
	"time"
	log "github.com/sirupsen/logrus"
	"github.com/andy2046/rund"
	"github.com/pkg/errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/wolfeidau/dynalock/v2"
)

func (c *Client) Destroy() error {
	run := rund.New()
	updateDestroying := rund.NewFuncOperator(func() error {
		globalStore := dynalock.New(dynamodb.New(c.Cfg), "hyperspike", "Agent")
		return globalStore.Put(context.TODO(), c.Id, dynalock.WriteWithAttributeValue(&dynamodb.AttributeValue{S: aws.String("DESTROYING")}), dynalock.WriteWithNoExpires())
	})
	run.AddNode("destroying", updateDestroying)

	destroyKeyFN := rund.NewFuncOperator(func() error {
		key, err := c.getState("kms", true)
		if err != nil {
			return err
		}
		return c.destroyKMS(key[0])
	})
	run.AddNode("key", destroyKeyFN)

	destroySecretFn := rund.NewFuncOperator(func() error {
		secret, err := c.getState("nodeSecret", true)
		if err != nil {
			return err
		}
		return c.destroySecret(secret[0])
	})
	run.AddNode("secret", destroySecretFn)
	destroySecretAdminFn := rund.NewFuncOperator(func() error {
		secretAdmin, err := c.getState("adminSecret", true)
		if err != nil {
			return err
		}
		return c.destroySecret(secretAdmin[0])
	})
	run.AddNode("secretAdmin", destroySecretAdminFn)

	destroyNodeRoleFn := rund.NewFuncOperator(func() error {
		return c.destroyRole("node-"+c.Id)
	})
	run.AddNode("nodeRole", destroyNodeRoleFn)
	run.AddEdge("nodeTemplate", "nodeRole")
	destroyMasterRoleFn := rund.NewFuncOperator(func() error {
		return c.destroyRole("master-"+c.Id)
	})
	run.AddNode("masterRole", destroyMasterRoleFn)
	run.AddEdge("masterTemplate", "masterRole")

	destroyClusterAutoscaleRoleFn := rund.NewFuncOperator(func() error {
		return c.destroyRole("cluster-autoscaler-"+c.Id)
	})
	run.AddNode("clusterAutoscaleRole", destroyClusterAutoscaleRoleFn)
	destroyClusterAutoscalePolicyFn := rund.NewFuncOperator(func() error {
		caPolicy, err := c.getState("clusterAutoscalerPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(caPolicy[0])
	})
	run.AddNode("clusterAutoscalePolicy", destroyClusterAutoscalePolicyFn)
	run.AddEdge("clusterAutoscaleRole", "clusterAutoscalePolicy")

	destroyNodeTerminatorRoleFn := rund.NewFuncOperator(func() error {
		return c.destroyRole("node-terminator-"+c.Id)
	})
	run.AddNode("nodeTerminatorRole", destroyNodeTerminatorRoleFn)
	destroyNodeTerminatorPolicyFn := rund.NewFuncOperator(func() error {
		caPolicy, err := c.getState("nodeTerminatorPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(caPolicy[0])
	})
	run.AddNode("nodeTerminatorPolicy", destroyNodeTerminatorPolicyFn)
	run.AddEdge("nodeTerminatorRole", "nodeTerminatorPolicy")

	destroyNodeTerminatorSQSFn := rund.NewFuncOperator(func() error {
		url, err := c.getState("nodeTerminatorSQS", true)
		if err != nil {
			return err
		}
		return c.destroySQS(url[0])
	})
	run.AddNode("nodeTerminatorSQS", destroyNodeTerminatorSQSFn)

	destroyMasterPolicyFn := rund.NewFuncOperator(func() error {
		masterPolicy, err := c.getState("masterGeneralPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(masterPolicy[0])
	})
	run.AddNode("masterPolicy", destroyMasterPolicyFn)
	run.AddEdge("masterRole", "masterPolicy")
	destroyNodePolicyFn := rund.NewFuncOperator(func() error {
		nodePolicy, err := c.getState("nodeGeneralPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(nodePolicy[0])
	})
	run.AddNode("nodePolicy", destroyNodePolicyFn)
	run.AddEdge("nodeRole", "nodePolicy")
	destroyIrsaPolicyFn := rund.NewFuncOperator(func() error {
		irsaPolicy, err := c.getState("irsaPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(irsaPolicy[0])
	})
	run.AddNode("irsaPolicy", destroyIrsaPolicyFn)
	run.AddEdge("masterRole", "irsaPolicy")
	destroyKeyPolicyFn := rund.NewFuncOperator(func() error {
		keyPolicy, err := c.getState("ebsPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(keyPolicy[0])
	})
	run.AddNode("keyPolicy", destroyKeyPolicyFn)
	run.AddEdge("masterRole", "keyPolicy")
	destroySecretReadPolicyFn := rund.NewFuncOperator(func() error {
		secretReadPolicy, err := c.getState("secretReadPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(secretReadPolicy[0])
	})
	run.AddNode("secretReadPolicy", destroySecretReadPolicyFn)
	run.AddEdge("masterRole", "secretReadPolicy")
	run.AddEdge("nodeRole", "secretReadPolicy")
	destroySecretWritePolicyFn := rund.NewFuncOperator(func() error {
		secretWritePolicy, err := c.getState("secretWritePolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(secretWritePolicy[0])
	})
	run.AddNode("secretWritePolicy", destroySecretWritePolicyFn)
	run.AddEdge("masterRole", "secretWritePolicy")
	destroyTableReadPolicyFn := rund.NewFuncOperator(func() error {
		tableReadPolicy, err := c.getState("tableReadPolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(tableReadPolicy[0])
	})
	run.AddNode("tableReadPolicy", destroyTableReadPolicyFn)
	run.AddEdge("masterRole", "tableReadPolicy")
	run.AddEdge("nodeRole", "tableReadPolicy")
	destroyTableWritePolicyFn := rund.NewFuncOperator(func() error {
		tableWritePolicy, err := c.getState("tableWritePolicy", true)
		if err != nil {
			return err
		}
		return c.destroyPolicy(tableWritePolicy[0])
	})
	run.AddNode("tableWritePolicy", destroyTableWritePolicyFn)
	run.AddEdge("masterRole", "tableWritePolicy")

	destroyElbFn := rund.NewFuncOperator(func() error {
		return c.destroyElb("master-lb-"+c.Id)
	})
	run.AddNode("elb", destroyElbFn)

	destroyASGNodeAFn := rund.NewFuncOperator(func() error {
		return c.destroyASG("node-"+c.Id+"-a")
	})
	run.AddNode("asgNodeA", destroyASGNodeAFn)
	run.AddEdge("asgNodeA", "nodeTemplate")
	destroyASGNodeBFn := rund.NewFuncOperator(func() error {
		return c.destroyASG("node-"+c.Id+"-b")
	})
	run.AddNode("asgNodeB", destroyASGNodeBFn)
	run.AddEdge("asgNodeB", "nodeTemplate")
	destroyASGNodeCFn := rund.NewFuncOperator(func() error {
		return c.destroyASG("node-"+c.Id+"-c")
	})
	run.AddNode("asgNodeC", destroyASGNodeCFn)
	run.AddEdge("asgNodeC", "nodeTemplate")
	destroyASGMasterAFn := rund.NewFuncOperator(func() error {
		return c.destroyASG("master-"+c.Id+"-a")
	})
	run.AddNode("asgMasterA", destroyASGMasterAFn)
	run.AddEdge("asgMasterA", "masterTemplate")
	destroyASGMasterBFn := rund.NewFuncOperator(func() error {
		return c.destroyASG("master-"+c.Id+"-b")
	})
	run.AddNode("asgMasterB", destroyASGMasterBFn)
	run.AddEdge("asgMasterB", "masterTemplate")
	destroyASGMasterCFn := rund.NewFuncOperator(func() error {
		return c.destroyASG("master-"+c.Id+"-c")
	})
	run.AddNode("asgMasterC", destroyASGMasterCFn)
	run.AddEdge("asgMasterC", "masterTemplate")

	destroyFirewallFn := rund.NewFuncOperator(func() error {
		fw, err := c.getState("fwA", true)
		if err != nil {
			return err
		}
		return c.terminateInstance(fw[0])
	})
	run.AddNode("firewall", destroyFirewallFn)

	destroyOIDCFn := rund.NewFuncOperator(func() error {
		arn, err := c.getState("oidcIrsa", true)
		if err != nil {
			return err
		}
		return c.destroyOIDC(arn[0])
	})
	run.AddNode("oidcIrsa", destroyOIDCFn)

	destroyNodeTemplateFn := rund.NewFuncOperator(func() error {
		return c.destroyTemplate("node-"+c.Id)
	})
	run.AddNode("nodeTemplate", destroyNodeTemplateFn)
	destroyMasterTemplateFn := rund.NewFuncOperator(func() error {
		return c.destroyTemplate("master-"+c.Id)
	})
	run.AddNode("masterTemplate", destroyMasterTemplateFn)

	destroyIRSABucketFn := rund.NewFuncOperator(func() error {
		//bucket, err := c.getState("irsaBucket", true)
		//if err != nil {
		//	return err
		//}
		bucket := c.Id + "-irsa"
		if err := c.emptyBucket(bucket) ; err != nil {
			log.Error("failed to empty IRSA bucket")
			return err
		}
		return c.destroyBucket(bucket)
	})
	run.AddNode("irsaBucket", destroyIRSABucketFn)

	destroySSHKeysFn := rund.NewFuncOperator(func() error {
		return c.destroyKeys("bastion-"+c.Id)
	})
	run.AddNode("sshKeys", destroySSHKeysFn)

	destroySubnetNodeAFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("nodeA", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetNodeA", destroySubnetNodeAFn)
	run.AddEdge("asgNodeA", "subnetNodeA")
	run.AddEdge("subnetNodeA", "vpc")
	destroySubnetNodeBFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("nodeB", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetNodeB", destroySubnetNodeBFn)
	run.AddEdge("asgNodeB", "subnetNodeB")
	run.AddEdge("subnetNodeB", "vpc")
	destroySubnetNodeCFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("nodeC", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetNodeC", destroySubnetNodeCFn)
	run.AddEdge("asgNodeC", "subnetNodeC")
	run.AddEdge("subnetNodeC", "vpc")

	destroySubnetEdgeAFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("edgeA", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetEdgeA", destroySubnetEdgeAFn)
	run.AddEdge("firewall", "subnetEdgeA")
	run.AddEdge("subnetEdgeA", "vpc")
	destroySubnetEdgeBFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("edgeB", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetEdgeB", destroySubnetEdgeBFn)
	run.AddEdge("subnetEdgeB", "vpc")
	destroySubnetEdgeCFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("edgeC", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetEdgeC", destroySubnetEdgeCFn)
	run.AddEdge("subnetEdgeC", "vpc")

	destroySubnetMasterAFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("masterA", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetMasterA", destroySubnetMasterAFn)
	run.AddEdge("asgMasterA", "subnetMasterA")
	run.AddEdge("subnetMasterA", "vpc")
	destroySubnetMasterBFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("masterB", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetMasterB", destroySubnetMasterBFn)
	run.AddEdge("asgMasterB", "subnetMasterB")
	run.AddEdge("subnetMasterB", "vpc")
	destroySubnetMasterCFn := rund.NewFuncOperator(func() error {
		subnet, err := c.getState("masterC", true)
		if err != nil {
			return err
		}
		return c.destroySubnet(subnet[0])
	})
	run.AddNode("subnetMasterC", destroySubnetMasterCFn)
	run.AddEdge("asgMasterC", "subnetMasterC")
	run.AddEdge("subnetMasterC", "vpc")

	destroySGNodeFn := rund.NewFuncOperator(func() error {
		sg, err := c.getState("nodeSg", true)
		if err != nil {
			return err
		}
		return c.destroySG(sg[0])
	})
	run.AddNode("sgNode", destroySGNodeFn)
	run.AddEdge("asgNodeA", "sgNode")
	run.AddEdge("asgNodeB", "sgNode")
	run.AddEdge("asgNodeC", "sgNode")
	run.AddEdge("sgNode", "vpc")
	destroySGMasterFn := rund.NewFuncOperator(func() error {
		sg, err := c.getState("masterSg", true)
		if err != nil {
			return err
		}
		return c.destroySG(sg[0])
	})
	run.AddNode("sgMaster", destroySGMasterFn)
	run.AddEdge("asgMasterA", "sgMaster")
	run.AddEdge("asgMasterB", "sgMaster")
	run.AddEdge("asgMasterC", "sgMaster")
	run.AddEdge("sgMaster", "vpc")
	destroySGMasterLBFn := rund.NewFuncOperator(func() error {
		sg, err := c.getState("masterLBSg", true)
		if err != nil {
			return err
		}
		return c.destroySG(sg[0])
	})
	run.AddNode("sgMasterLB", destroySGMasterLBFn)
	run.AddEdge("elb", "sgMasterLB")
	run.AddEdge("asgMasterA", "sgMasterLB")
	run.AddEdge("asgMasterB", "sgMasterLB")
	run.AddEdge("asgMasterC", "sgMasterLB")
	run.AddEdge("sgMasterLB", "vpc")
	destroySGEdgeFn := rund.NewFuncOperator(func() error {
		sg, err := c.getState("edgeSg", true)
		if err != nil {
			return err
		}
		return c.destroySG(sg[0])
	})
	run.AddNode("sgEdge", destroySGEdgeFn)
	run.AddEdge("firewall", "sgEdge")
	run.AddEdge("sgEdge", "vpc")

	destroyGatewayFn := rund.NewFuncOperator(func() error {
		gateway, err := c.getState("gw", true)
		if err != nil {
			return err
		}
		vpc, err := c.getState("vpc", true)
		if err != nil {
			return err
		}
		return c.destroyGateway(gateway[0], vpc[0])
	})
	run.AddNode("gateway", destroyGatewayFn)
	run.AddEdge("gateway", "vpc")

	destroyNatRouteFn := rund.NewFuncOperator(func() error {
		route, err := c.getState("natRoute", true)
		if err != nil {
			return err
		}
		return c.destroyRouteTable(route[0])
	})
	run.AddNode("natRoute", destroyNatRouteFn)
	run.AddEdge("firewall", "natRoute")
	run.AddEdge("natRoute", "vpc")

	destroyGWRouteFn := rund.NewFuncOperator(func() error {
		route, err := c.getState("gwRoute", true)
		if err != nil {
			return err
		}
		return c.destroyRouteTable(route[0])
	})
	run.AddNode("gwRoute", destroyGWRouteFn)
	run.AddEdge("gwRoute", "vpc")

	destroyVPCFn := rund.NewFuncOperator(func() error {
		vpc, err := c.getState("vpc", true)
		if err != nil {
			return err
		}
		return c.destroyVPC(vpc[0])
	})
	run.AddNode("vpc", destroyVPCFn)
	run.AddEdge("asgNodeA", "vpc")
	run.AddEdge("asgNodeB", "vpc")
	run.AddEdge("asgNodeC", "vpc")
	run.AddEdge("asgMasterA", "vpc")
	run.AddEdge("asgMasterB", "vpc")
	run.AddEdge("asgMasterC", "vpc")
	run.AddEdge("firewall", "vpc")

	destroyTableFn := rund.NewFuncOperator(func() error {
		return c.destroyTable(c.Id)
	})
	run.AddNode("table", destroyTableFn)
	run.AddEdge("vpc", "table")
	run.AddEdge("irsaBucket", "table")
	run.AddEdge("irsaPolicy", "table")
	run.AddEdge("nodePolicy", "table")
	run.AddEdge("masterPolicy", "table")
	run.AddEdge("secretWritePolicy", "table")
	run.AddEdge("tableReadPolicy", "table")
	run.AddEdge("tableWritePolicy", "table")
	run.AddEdge("keyPolicy", "table")
	run.AddEdge("secretReadPolicy", "table")
	run.AddEdge("oidcIrsa", "table")
	run.AddEdge("key", "table")


	finishDestroying := rund.NewFuncOperator(func() error {
		globalStore := dynalock.New(dynamodb.New(c.Cfg), "hyperspike", "Agent")
		return globalStore.Delete(context.TODO(), c.Id)
	})
	run.AddNode("finish", finishDestroying)
	run.AddEdge("table", "finish")

	if err := run.Run(); err != nil {
		log.Errorf("failed to destroy on graph traversal: %v", err)
		return err
	}

	log.Infof("successfully deleted cluster %s", c.Id)

	return nil
}

func (c *Client) destroyKMS(id string) error {
	svc := kms.New(c.Cfg)
	input := &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(id),
		PendingWindowInDays: aws.Int64(7),
	}

	req := svc.ScheduleKeyDeletionRequest(input)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeNotFoundException:
				log.Println(kms.ErrCodeNotFoundException, aerr.Error())
			case kms.ErrCodeInvalidArnException:
				log.Println(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				log.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeKMSInternalException:
				log.Println(kms.ErrCodeKMSInternalException, aerr.Error())
			case kms.ErrCodeKMSInvalidStateException:
				log.Println(kms.ErrCodeKMSInvalidStateException, aerr.Error())
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

func (c *Client) destroySecret(id string) error {
	svc := secretsmanager.New(c.Cfg)
	input := &secretsmanager.DeleteSecretInput{
		ForceDeleteWithoutRecovery: aws.Bool(true),
		SecretId: aws.String(id),
	}
	req := svc.DeleteSecretRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeResourceNotFoundException:
				log.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			case secretsmanager.ErrCodeInvalidParameterException:
				log.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidRequestException:
				log.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				log.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
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

func (c *Client) destroyRole(name string) error {
	var limit int = 90
	var count int = 0

	svc := iam.New(c.Cfg)
	list := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(name),
	}
	listReq := svc.ListAttachedRolePoliciesRequest(list)
	listResp, err := listReq.Send(context.TODO())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				log.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeUnmodifiableEntityException:
				log.Println(iam.ErrCodeUnmodifiableEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		return err;
	}
	for _, p := range listResp.AttachedPolicies {
		det := &iam.DetachRolePolicyInput{
			PolicyArn: p.PolicyArn,
			RoleName: aws.String(name),
		}
		req := svc.DetachRolePolicyRequest(det)
		_, err = req.Send(context.TODO())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == iam.ErrCodeNoSuchEntityException {
					log.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
					break
				}
				log.Error(aerr.Error())
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Error(err.Error())
			}
			return err
		}
	}
	for {
		svc := iam.New(c.Cfg)
		input := &iam.RemoveRoleFromInstanceProfileInput{
			InstanceProfileName: aws.String(name),
			RoleName:            aws.String(name),
		}

		req := svc.RemoveRoleFromInstanceProfileRequest(input)
		_, err := req.Send(context.TODO())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == iam.ErrCodeNoSuchEntityException {
					log.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
					break
				}
				log.Error(aerr.Error())
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Error(err.Error())
			}
			count++
			time.Sleep(5 * time.Second)
			if count >= limit {
				return errors.New("timed out waiting for profile "+name+" to delete")
			}
		} else {
			break
		}
	}

	count = 0
	for {
		input := &iam.DeleteInstanceProfileInput{
			InstanceProfileName: aws.String(name),
		}

		svc := iam.New(c.Cfg)
		req := svc.DeleteInstanceProfileRequest(input)
		_, err := req.Send(context.TODO())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() == iam.ErrCodeNoSuchEntityException {
					log.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
					break
				}
				log.Error(aerr.Error())
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Error(err.Error())
			}
			count++
			time.Sleep(5 * time.Second)
			if count >= limit {
				return errors.New("timed out waiting for profile "+name+" to delete")
			}
		} else {
			break
		}
	}
	count = 0
	for {
		svc := iam.New(c.Cfg)
		role := &iam.DeleteRoleInput{
			RoleName: aws.String(name),
		}

		reqRole := svc.DeleteRoleRequest(role)
		_, err := reqRole.Send(context.TODO())
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					log.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeDeleteConflictException:
					log.Println(iam.ErrCodeDeleteConflictException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					log.Println(iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeUnmodifiableEntityException:
					log.Println(iam.ErrCodeUnmodifiableEntityException, aerr.Error())
				case iam.ErrCodeConcurrentModificationException:
					log.Println(iam.ErrCodeConcurrentModificationException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					log.Println(iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					log.Error(aerr.Error())
				}
			} else {
				// Print the error, cast err to awserr.Error to get the Code and
				// Message from an error.
				log.Error(err.Error())
			}
			count++
			time.Sleep(5 * time.Second)
			if count >= limit {
				return errors.New("timed out waiting for profile "+name+"to delete")
			}
		} else {
			break
		}
	}
	return nil
}

func (c *Client) destroyPolicy(arn string) error {
	svc := iam.New(c.Cfg)
	input := &iam.DeletePolicyInput{
		PolicyArn: aws.String(arn),
	}
	req := svc.DeletePolicyRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		log.Errorf("failed to delete policy %s, %v", arn, err)
		return err
	}
	return nil
}

func (c *Client) destroyOIDC(arn string) error {
	svc := iam.New(c.Cfg)
	input := &iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(arn),
	}
	req := svc.DeleteOpenIDConnectProviderRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		log.Errorf("failed to destroy OIDC provider %s, %v", arn, err)
		return err
	}
	return nil
}

func (c *Client) destroyElb(id string) error {
	svc := elasticloadbalancing.New(c.Cfg)
	input := &elasticloadbalancing.DeleteLoadBalancerInput{
		LoadBalancerName: aws.String(id),
	}

	req := svc.DeleteLoadBalancerRequest(input)
	_, err := req.Send(context.TODO())
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

func (c *Client) terminateInstance(id string) error {
	input := &ec2.TerminateInstancesInput{
		InstanceIds: []string{
			id,
		},
	}

	req := c.Ec2.TerminateInstancesRequest(input)
	_, err := req.Send(context.TODO())
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

func (c *Client) destroySQS(url string) error {
	svc := sqs.New(c.Cfg)

	input := &sqs.DeleteQueueInput{
		QueueUrl: aws.String(url),
	}

	req := svc.DeleteQueueRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			log.Error(aerr.Error())
		} else {
			log.Error(err.Error())
		}
		return err
	}
	return nil
}

func (c *Client) destroyASG(name string) error {
	svc := autoscaling.New(c.Cfg)

	input := &autoscaling.DeleteAutoScalingGroupInput{
		AutoScalingGroupName: aws.String(name),
		ForceDelete:          aws.Bool(true),
	}

	req := svc.DeleteAutoScalingGroupRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case autoscaling.ErrCodeScalingActivityInProgressFault:
				log.Println(autoscaling.ErrCodeScalingActivityInProgressFault, aerr.Error())
			case autoscaling.ErrCodeResourceInUseFault:
				log.Println(autoscaling.ErrCodeResourceInUseFault, aerr.Error())
			case autoscaling.ErrCodeResourceContentionFault:
				log.Println(autoscaling.ErrCodeResourceContentionFault, aerr.Error())
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

func (c *Client) destroyTemplate(name string) error {
	svc := autoscaling.New(c.Cfg)
	input := &autoscaling.DeleteLaunchConfigurationInput{
		LaunchConfigurationName: aws.String(name),
	}
	req := svc.DeleteLaunchConfigurationRequest(input)
	_, err := req.Send(context.TODO())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case autoscaling.ErrCodeResourceInUseFault:
				log.Println(autoscaling.ErrCodeResourceInUseFault, aerr.Error())
			case autoscaling.ErrCodeResourceContentionFault:
				log.Println(autoscaling.ErrCodeResourceContentionFault, aerr.Error())
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

func (c *Client) emptyBucket(name string) error {
	svc := s3.New(c.Cfg)
	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(name),
		Delete: &s3.Delete{
			Objects: []s3.ObjectIdentifier{
				{
					Key: aws.String("keys.json"),
				},
				{
					Key: aws.String(".well-known/openid-configuration"),
				},
			},
		},
	}

	req := svc.DeleteObjectsRequest(input)
	_, err := req.Send(context.TODO())
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

func (c *Client) destroyBucket(name string) error {
	svc := s3.New(c.Cfg)
	input := &s3.DeleteBucketInput{
		Bucket: aws.String(name),
	}

	req := svc.DeleteBucketRequest(input)
	_, err := req.Send(context.TODO())
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

func (c *Client) destroyKeys(name string) error {
	input := &ec2.DeleteKeyPairInput{
		KeyName: aws.String(name),
	}

	req := c.Ec2.DeleteKeyPairRequest(input)
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

func (c *Client) destroyVPC(id string) error {
	input := &ec2.DeleteVpcInput{
		VpcId: aws.String(id),
	}
	limit := 120 // 10 minutes
	count := 0
	for {
		svc := ec2.New(c.Cfg)
		req := svc.DeleteVpcRequest(input)
		_, err := req.Send(context.TODO())
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
			count++
			time.Sleep(5 * time.Second)
			if count >= limit {
				return errors.New("timed out waiting for VPC "+id+" to delete")
			}
		} else {
			break
		}
	}
	return nil
}

func (c *Client) destroySG(id string) error {
	input := &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(id),
	}

	var count int = 0
	var limit int = 90

	describe := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{
			id,
		},
	}

	describeReq := c.Ec2.DescribeSecurityGroupsRequest(describe)
	describeRes, err := describeReq.Send(context.TODO())
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

	revoke := &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(id),
		IpPermissions: describeRes.SecurityGroups[0].IpPermissions,
	}
	revokeReq :=  c.Ec2.RevokeSecurityGroupIngressRequest(revoke)
	_, err = revokeReq.Send(context.TODO())
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
	for {
		req := c.Ec2.DeleteSecurityGroupRequest(input)
		_, err := req.Send(context.TODO())
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
			time.Sleep(5 * time.Second)
			if count > limit {
				return errors.New("timedout waiting to destroy sercurity group")
			}
			count++
		} else {
			break
		}
	}
	return nil
}

func (c *Client) destroySubnet(id string) error {
	input := &ec2.DeleteSubnetInput{
		SubnetId: aws.String(id),
	}

	var count int = 0
	var limit int = 90
	for {
		req := c.Ec2.DeleteSubnetRequest(input)
		_, err := req.Send(context.TODO())
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
			time.Sleep(5 * time.Second)
			if count > limit {
				return errors.New("timedout waiting to destroy subnet "+id)
			}
			count++
		} else {
			break
		}
	}
	return nil
}

func (c *Client) destroyGateway(id, vpc string) error {
	input := &ec2.DeleteInternetGatewayInput{
		InternetGatewayId: aws.String(id),
	}
	det := &ec2.DetachInternetGatewayInput{
		InternetGatewayId: aws.String(id),
		VpcId:             aws.String(vpc),
	}
	var count int = 0
	var limit int = 90
	for {
		reqDet := c.Ec2.DetachInternetGatewayRequest(det)
		_, err := reqDet.Send(context.TODO())
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
			time.Sleep(5 * time.Second)
			if count > limit {
				return errors.New("timedout waiting to destroy gateway")
			}
			count++
		} else {
			break
		}
	}

	count = 0
	for {
		req := c.Ec2.DeleteInternetGatewayRequest(input)
		_, err := req.Send(context.TODO())
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
			time.Sleep(5 * time.Second)
			if count > limit {
				return errors.New("timedout waiting to destroy gateway")
			}
			count++
		} else {
			break
		}
	}

	return nil
}

func (c *Client) destroyRouteTable(id string) error {
	input := &ec2.DeleteRouteTableInput{
		RouteTableId: aws.String(id),
	}

	var count int = 0
	var limit int = 90
	for {
		req := c.Ec2.DeleteRouteTableRequest(input)
		_, err := req.Send(context.TODO())
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
			time.Sleep(5 * time.Second)
			if count > limit {
				return errors.New("timedout waiting to destroy routetable")
			}
			count++
		} else {
			break
		}
	}
	return nil
}

func (c *Client) destroyTable(name string) error {
	svc := dynamodb.New(c.Cfg)
	input := &dynamodb.DeleteTableInput{
		TableName: aws.String(name),
	}

	req := svc.DeleteTableRequest(input)
	_, err := req.Send(context.Background())
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeResourceInUseException:
				log.Println(dynamodb.ErrCodeResourceInUseException, aerr.Error())
			case dynamodb.ErrCodeResourceNotFoundException:
				log.Println(dynamodb.ErrCodeResourceNotFoundException, aerr.Error())
			case dynamodb.ErrCodeLimitExceededException:
				log.Println(dynamodb.ErrCodeLimitExceededException, aerr.Error())
			case dynamodb.ErrCodeInternalServerError:
				log.Println(dynamodb.ErrCodeInternalServerError, aerr.Error())
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
