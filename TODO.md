* [x] Tag based AMI search.
* [-] Boot command
  * [x] join-nodes
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Get token from secrets-manager
    - [x] Join node
  * [-] join-masters
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock
    - [x] Check for Initialized
    - [ ] Check version
    - [x] Join ring
  * [-] bootstrap-master
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [x] Check for lock in dynamo
    - [x] Get lock in dynamo
    - [ ] check initialized-flag
    - [x] upload keys to secrets-manager -> this might be better served as a Daemon on the cluster
    - [ ] set initialized-flag in dynamo
    - [ ] cilium
    - [ ] cloud-controller
    - [ ] IRSA
* [x] Shell Completion
* [-] Switch from fmt to log (like argonaut)
* [ ] Refactor to add concurrency
* [x] Util function to calculate subnets
* [ ] Support automated upgrades
* [ ] set metadata in dynamodb
  * IP ( auto calculated )
  * Service subnet ( Optional )
  * Pod subnet ( Optional )
  * cluster name ( Optional / Generated )
  * elb dns ( Calculated )
  * region ( Calculated )
  * external dns ( Optional )
* [ ] support cilium etcd and etcd-operator (optional)
* [ ] support gitifold (optional)
* [ ] support ingress (optional, requires )
* [ ] support CI (optional, requires ingress)
* [ ] support CD (optional, requires ingress)
* [ ] support Monitoring (optional, requires ingess)
* [ ] support Multi-Cluster Mesh (optional)
* [ ] Cluster Util components ( Create outside of instances )
  * [ ] Node
    - [ ] Secret-Manager
    - [ ] Dynamo
    - [ ] ELB
  * [ ] Master
    - [ ] Dynamo
    - [ ] Secret-Manager
  * [ ] Auth
    - [ ] Roles
    - [ ] S3