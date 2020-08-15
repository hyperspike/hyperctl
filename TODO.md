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
    - [ ] Check for lock
    - [ ] Check for Initialized
    - [ ] Check version
    - [ ] Join ring
  * [-] bootstrap-master
    - [x] Calculate Cluster-name, and Node Type
    - [x] Fetch cluster info from dynamo (secret-name and cluster address)
    - [ ] Check for lock in dynamo
    - [ ] Get lock in dynamo
    - [ ] check initialized-flag
    - [ ] upload keys to secrets-manager -> this might be better served as a Daemon on the cluster
    - [ ] set initialized-flag in dynamo
    - [ ] cilium
    - [ ] cloud-controller
    - [ ] IRSA
* [x] Shell Completion
* [ ] Switch from fmt to log (like argonaut)
* [x] Util function to calculate subnets
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
