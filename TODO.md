
## Current Status

Everything upto the admin.conf uploader has been written. Control plane has been tested and verified, node join has been reworked, but should work. Need to do final testing on IRSA then MVP will be done.

## MVP

<details><summary>See List</summary>
<p>

* [x] Tag based AMI search.
* [x] Boot command
  * [x] join-nodes
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Get token from secrets-manager
    - [x] Join node
  * [x] join-masters
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock
    - [x] Check for Initialized
    - [x] api-server-aws-kms
    - [x] Join ring
  * [x] bootstrap-master
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock in dynamo
    - [x] Get lock in dynamo
    - [x] check initialized-flag
    - [x] upload keys to secrets-manager -> this might be better served as a Daemon on the cluster
    - [x] set initialized-flag in dynamo
    - [x] kubeadm config template
    - [x] kustomize template
    - [x] Embed kube client and upload configs
      - [x] cilium
      - [x] cloud-controller ( should probably pull in PR to fix multi-eni )
      - [x] irsa deployment
    - [x] api-server-aws-kms
    - [x] IRSA Upload
* [x] Shell Completion
* [x] Util function to calculate subnets
* [x] Embed version at build time
* [x] Create version from git tag
* [x] set metadata in dynamodb
  * [x] IP ( auto calculated )
  * [x] Service subnet ( Optional )
  * [x] Pod subnet ( Optional )
  * [x] cluster name ( Optional / Generated )
  * [x] elb dns ( Calculated )
  * [x] region ( Calculated )
* [x] Cluster Util components ( Create outside of instances )
  * [x] Meta
    - [x] DynamoDB
    - [x] Secrets-Manager
  * [x] Node
    - [x] Launch Config
    - [x] ASG
  * [x] Master
    - [x] API-Server secrets kms key
    - [x] Launch Config
    - [x] ASG
    - [x] IRSA S3
    - [x] IRSA OpenID IAM
  * [x] Auth
    - [x] Roles
* [x] upload admin.conf to secrets-manager, and support fetch to local

</p>
</details>

## Alpha

* [ ] More Kubernetes configs; cilium, psp, servicemonitors, resource requests, metrics-server, network policies
  * [ ] Cilium to leverage cilium-cli libriaries for deployment
* [ ] aws-ebs-csi
* [-] Config options
  * [ ] existing vpc
  * [x] control-plane size
  * [x] worker size
* [-] Support automated upgrades, can probably just update the launch config via an on-cluster daemon
* [ ] Support Additional User-Set Tags
* [ ] autocomplete on remote state search
* [x] structured logging for cri-o and kubernetes
* [x] Split logging into; to file on server and console on workstation
* [x] nat instances per zone
* [x] Better cli ergonomics
* [x] cluster-autoscaler
* [x] aws-node-terminator (deployment on master not daemonset)
* [x] cleanup AMI building, faster, better caching, pipeline based
* [x] Refactor to add concurrency, use directed acyclic graph for dependency mapping?
* [x] fix alpine ami image
* [x] Track state for destruction
* [x] Track global state
* [x] cluster destroy
* [x] Switch from fmt to log (like argonaut)
* [x] Automatically detect availability zones
* [x] upload etcd-healthcheck-client keys
* [x] automated e2e

## Beta

* [ ] Upgrade aws library
* [ ] Support metal
* [ ] Support OCI?
* [ ] move secret and cert management to vault and support bootstraping
* [ ] convert nat instances to ASGs
* [ ] arm support / graviton2 (not going to bother with user facing CLI, just machine images)
* [x] falco
* [ ] Terraform provider
* [ ] cluster-api provider and bootstrap
* [ ] Edge node VPN access ( voucher + cilium )
* [ ] Plugins
  * [ ] support cilium-etcd and etcd-operator (optional)
  * [ ] support Multi-Cluster Mesh (optional, requires cilium-etcd)
  * [ ] support Gitifold (optional)
  * [ ] support ingress (optional, requires )
  * [ ] support CI (optional, requires ingress)
  * [ ] support CD (optional, requires ingress)
  * [ ] support Monitoring (optional, requires ingess)
* [ ] GCP Support
