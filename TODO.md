
## Current Status

* All command components for MVP have been created and tested. Cluster Join has been tested. Cluster upload needs to be tested.

## MVP

* [x] Tag based AMI search.
* [ ] Boot command
  * [x] join-nodes
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Get token from secrets-manager
    - [x] Join node
  * [ ] join-masters
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock
    - [x] Check for Initialized
    - [x] api-server-aws-kms
    - [ ] Check version
    - [x] Join ring
  * [ ] bootstrap-master
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock in dynamo
    - [x] Get lock in dynamo
    - [x] check initialized-flag
    - [x] upload keys to secrets-manager -> this might be better served as a Daemon on the cluster
    - [x] set initialized-flag in dynamo
    - [x] kubeadm config template
    - [x] kustomize template
    - [ ] Embed kube client and upload configs
      - [ ] cilium
      - [ ] cloud-controller ( should probably pull in PR to fix multi-eni )
      - [ ] irsa deployment
    - [x] api-server-aws-kms
    - [ ] IRSA Upload
* [x] Shell Completion
* [x] Util function to calculate subnets
* [x] Embed version at build time
* [x] Create version from git tag
* [ ] set metadata in dynamodb
  * [x] IP ( auto calculated )
  * [x] Service subnet ( Optional )
  * [x] Pod subnet ( Optional )
  * [x] cluster name ( Optional / Generated )
  * [x] elb dns ( Calculated )
  * [x] region ( Calculated )
  * [ ] external dns ( Optional )
* [ ] Cluster Util components ( Create outside of instances )
  * [x] Meta
    - [x] DynamoDB
    - [x] Secrets-Manager
  * [x] Node
    - [x] Launch Config
    - [x] ASG
  * [ ] Master
    - [x] API-Server secrets kms key
    - [x] Launch Config
    - [x] ASG
    - [x] IRSA S3
    - [x] IRSA OpenID IAM
      - [ ] write a quick daemon to perodically update the OpenID cert hash
  * [x] Auth
    - [x] Roles
* [ ] upload admin.conf to secrets-manager, and support fetch to local

## Alpha

* [ ] Refactor to add concurrency
* [ ] Support Additional User-Set Tags
* [ ] Track state for destruction
* [ ] cluster destroy
* [ ] Support automated upgrades, can probably just update the launch config via an on cluster daemon
* [ ] Switch from fmt to log (like argonaut)

## Beta

* [ ] Edge node VPN access
* [ ] Plugins
  * [ ] support cilium etcd and etcd-operator (optional)
  * [ ] support Multi-Cluster Mesh (optional, requires cilium-etcd)
  * [ ] support gitifold (optional)
  * [ ] support ingress (optional, requires )
  * [ ] support CI (optional, requires ingress)
  * [ ] support CD (optional, requires ingress)
  * [ ] support Monitoring (optional, requires ingess)
* [ ] Terraform provider
* [ ] cluster-api provider and bootstrap
* [ ] GCP Support
