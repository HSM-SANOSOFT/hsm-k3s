ufw disable

ufw allow 6443/tcp #apiserver
ufw allow from 10.42.0.0/16 to any #pods
ufw allow from 10.43.0.0/16 to any #services
set -e

K3S_VERSION="v1.26.5+k3s1"
K3S_KUBECONFIG_MODE="644"

echo ">>> Downloading K3s binary $K3S_VERSION..."
curl -Lo /usr/local/bin/k3s https://github.com/k3s-io/k3s/releases/download/$K3S_VERSION/k3s
chmod a+x /usr/local/bin/k3s

echo "K3s binary installed at /usr/local/bin/k3s"

 $K3S_KUBECONFIG_MODE k3s server

echo ">>> To start K3s manually:"
echo ">>> Run: k3s-start"

#sudo cat /var/lib/rancher/k3s/server/node-token
