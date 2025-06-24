#!/bin/bash
set -e

sudo swapoff -a

ufw allow 6443/tcp
ufw allow from 10.42.0.0/16 to any
ufw allow from 10.43.0.0/16 to any

curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --cluster-init --write-kubeconfig-mode=644" sh -

sudo chmod 644 /etc/rancher/k3s/k3s.yaml
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh && ./get_helm.sh

cat /var/lib/rancher/k3s/server/node-token

---------------------------------------------

#!/bin/bash
set -e

sudo swapoff -a

ufw allow 6443/tcp
ufw allow from 10.42.0.0/16 to any
ufw allow from 10.43.0.0/16 to any

K3S_URL=https://<DELL1_IP>:6443
K3S_TOKEN=<PASTE_TOKEN_HERE>

curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server" K3S_URL=$K3S_URL K3S_TOKEN=$K3S_TOKEN sh -

sudo chmod 644 /etc/rancher/k3s/k3s.yaml
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
