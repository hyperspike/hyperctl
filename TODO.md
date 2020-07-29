1) [x] Tag based AMI search.
2) [-] Boot command
  a) [-] node
    - [x] Calculate Cluster-name, and Node Type
    - [ ] Fetch cluster info from dynamo (secret-name and cluster address)
    - [ ] Get token from secrets-manager
    - [ ] Join node
  b) [-] masters
    - [x] Calculate Cluster-name, and Node Type
    - [ ] Fetch cluster info from dynamo (secret-name and cluster address)
    - [ ] Check for lock
    - [ ] Check for Initialized
    - [ ] Check version
    - [ ] Join ring
  c) [-] bootstrap-master
    - [ ] Check for lock in dynamo
    - [ ] Get lock in dynamo
    - [ ] check initialized-flag
    - [ ] upload keys to secrets-manager
    - [ ] set initialized-flag in dynamo
    - [ ] cilium
    - [ ] cloud-controller
    - [ ] IRSA
3) [x] Shell Completion
4) [ ] Switch from fmt to log (like argonaut)
