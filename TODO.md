
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
    - [ ] Check version
    - [x] Join ring
  * [ ] bootstrap-master
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock in dynamo
    - [x] Get lock in dynamo
    - [x] check initialized-flag
    - [x] upload keys to secrets-manager -> this might be better served as a Daemon on the cluster
    - [ ] set initialized-flag in dynamo
    - [ ] cilium
    - [ ] cloud-controller ( should probably pull in PR to fix multi-eni )
    - [ ] IRSA
* [x] Shell Completion
* [x] Util function to calculate subnets
* [x] Embed version at build time
* [x] Create version from git tag
* [ ] set metadata in dynamodb
  * IP ( auto calculated )
  * Service subnet ( Optional )
  * Pod subnet ( Optional )
  * cluster name ( Optional / Generated )
  * elb dns ( Calculated )
  * region ( Calculated )
  * external dns ( Optional )
* [ ] Cluster Util components ( Create outside of instances )
  * [ ] Meta
    - [ ] DynamoDB
    - [ ] Secrets-Manager
  * [ ] Node
    - [ ] Launch Config
    - [ ] ASG
  * [ ] Master
    - [ ] API-Server secrets kms key
    - [ ] Launch Config
    - [ ] ASG
    - [ ] IRSA S3
    - [ ] IRSA OpenID IAM
  * [ ] Auth
    - [ ] Roles
* [ ] upload admin.conf to secrets-manager, and support fetch to local

## Alpha

* [ ] Refactor to add concurrency
* [ ] Support Additional Tags
* [ ] Track state for destruction
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
* GCP Support
* 
