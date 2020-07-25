1) [x] Tag based AMI search.
2) [-] Boot command
  a) [ ] node
    - [ ] Get token from secrets-manager
    - [ ] Join node
  b) [ ] masters
    - [ ] Check for lock
    - [ ] check version
      * [ ] Bump AMI in Launch Template
      * [ ] Roll upgrade
    - [ ] Join ring
  c) bootstrap-master
    - [ ] Check for lock in dynamo
    - [ ] Get lock in dynamo
    - [ ] check initialized-flag
    - [ ] upload keys to secrets-manager
    - [ ] set initialized-flag in dynamo
    - [ ] cilium
    - [ ] cloud-controller
    - [ ] IRSA
