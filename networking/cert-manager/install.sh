#!/usr/bin/env bash
set -e

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
# 3. Install cert-manager CRDs first
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.18.2/cert-manager.yaml