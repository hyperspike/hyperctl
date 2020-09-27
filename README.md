# Hyperctl

[![Build Status](https://ci.hyperspike.io/api/badges/Hyperspike/hyperctl/status.svg)](https://ci.hyperspike.io/Hyperspike/hyperctl)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](COPYING)

Hyperctl is under heavy development, if a feature is missing come back in a few weeks.

To see a view of planned features go to the [TODO Page](TODO.md)

## About

The goal is to create a scalable, secure, bootstrapping mechanism, that reduces friction between AWS and kubernetes clusters.

Hyperctl is an initial deployment mechanism for Hyperspike Kubernetes infrastructure. While terraform, eks, kops, cluster-api and others are decent bootstrapping mechanisms they don't fully capture bootstrapped self hosted kubernetes while maintaining a GitOps audit trail.

The Hyperspike stack includes an Alpine base image, with cri-o container daemon, with crun container runtime. And cilium cni. Which necessitates a custom configured linux kernel for full eBPF support. On aws cilium is setup in ENI mode without kube-proxy.
