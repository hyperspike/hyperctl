# Hyperctl

[![Build Status](https://ci.hyperspike.io/api/badges/Hyperspike/hyperctl/status.svg?branch=main)](https://ci.hyperspike.io/Hyperspike/hyperctl)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](COPYING)

Hyperctl is under heavy development, if a feature is missing come back in a few weeks.

To see a view of planned features go to the [TODO Page](TODO.md)

## About

The goal is to create a scalable, secure, bootstrapping mechanism, that reduces friction between AWS and kubernetes clusters.

Hyperctl is an initial deployment mechanism for Hyperspike Kubernetes infrastructure. While terraform, eks, [kops](https://github.com/kubernetes/kops), [cluster-api](https://cluster-api.sigs.k8s.io/) and others are decent bootstrapping mechanisms they don't fully capture bootstrapped self hosted kubernetes while maintaining a GitOps audit trail.

The Hyperspike stack includes an [Alpine](https://alpinelinux.org/) base image, with [cri-o](https://github.com/cri-o/cri-o) container daemon, with [crun](https://github.com/containers/crun) container runtime, And [cilium](https://cilium.io/) cni. Which necessitates a custom configured Linux kernel for full eBPF support. On [AWS](https://github.com/aws/amazon-vpc-cni-k8s) cilium is setup in [ENI](https://docs.cilium.io/en/v1.8/concepts/networking/ipam/eni/) mode without [kube-proxy](https://docs.cilium.io/en/v1.8/gettingstarted/kubeproxy-free/).

Hyperctl is designed to work with [Gitifold](https://github.com/hyperspike/gitifold.git) to provide fully a full Infra and Application pipeline.

## Getting Started

Get hyperctl, you can download binaries from the release page: https://github.com/hyperspike/hyperctl/releases/latest

### First Cluster

You're going to need an AWS Account and API Credentials.

    export AWS_DEFAULT_REGION=us-east-2
    export AWS_SECRET_ACCESS_KEY=<herp-derp>
    export AWS_ACCESS_KEY_ID=<derp-herp>

Then create your first cluster:

    hyperctl boot

In addition to creating a cluster, the create command will drop 2 files into your current directory, a SSH key and kubeconfig, these can be used to ssh to your new bastion host and use your new cluster.

### Building From Source

To build hyperctl from source you will need [Golang](https://golang.org/) and [Make.](https://www.gnu.org/software/make/)

    go get -u hyperspike.io/hyperctl
    cd $GOPATH/src/hyperspike.io/hyperctl
    make local_install
