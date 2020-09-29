# Hyperctl

[![Build Status](https://ci.hyperspike.io/api/badges/Hyperspike/hyperctl/status.svg)](https://ci.hyperspike.io/Hyperspike/hyperctl)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](COPYING)

Hyperctl is under heavy development, if a feature is missing come back in a few weeks.

To see a view of planned features go to the [TODO Page](TODO.md)

## About

The goal is to create a scalable, secure, bootstrapping mechanism, that reduces friction between AWS and kubernetes clusters.

Hyperctl is an initial deployment mechanism for Hyperspike Kubernetes infrastructure. While terraform, eks, [kops](https://github.com/kubernetes/kops), [cluster-api](https://cluster-api.sigs.k8s.io/) and others are decent bootstrapping mechanisms they don't fully capture bootstrapped self hosted kubernetes while maintaining a GitOps audit trail.

The Hyperspike stack includes an [Alpine](https://alpinelinux.org/) base image, with [cri-o](https://github.com/cri-o/cri-o) container daemon, with [crun](https://github.com/containers/crun) container runtime, And [cilium](https://cilium.io/) cni. Which necessitates a custom configured Linux kernel for full eBPF support. On [AWS](https://github.com/aws/amazon-vpc-cni-k8s) cilium is setup in [ENI](https://docs.cilium.io/en/v1.8/concepts/networking/ipam/eni/) mode without [kube-proxy](https://docs.cilium.io/en/v1.8/gettingstarted/kubeproxy-free/).

Hyperctl is designed to work with [Gitifold](https://github.com/hyperspike/gitifold.git) to provide fully a full Infra and Application pipeline.
