
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

* [ ] More Cilium configs, hubble, psp, serviceMonitors
* [x] Refactor to add concurrency, use directed acyclic graph for dependency mapping?
* [ ] fix alpine ami image
* [ ] Support Additional User-Set Tags
* [ ] Track state for destruction
* [ ] Track global state
* [ ] autocomplete on remote state search
* [ ] cluster destroy
* [ ] Support automated upgrades, can probably just update the launch config via an on cluster daemon
* [x] Switch from fmt to log (like argonaut)
* [x] Automatically detect availability zones
* [ ] Split logging into; to file on server and console on workstation
* [x] upload etcd-healthcheck-client keys

## Beta

* [ ] arm support (not going to bother with user facing CLI, just machine images)
* [ ] Terraform provider
* [ ] Edge node VPN access
* [ ] Plugins
  * [ ] support cilium-etcd and etcd-operator (optional)
  * [ ] support Multi-Cluster Mesh (optional, requires cilium-etcd)
  * [ ] support gitifold (optional)
  * [ ] support ingress (optional, requires )
  * [ ] support CI (optional, requires ingress)
  * [ ] support CD (optional, requires ingress)
  * [ ] support Monitoring (optional, requires ingess)
* [ ] cluster-api provider and bootstrap
* [ ] GCP Support
