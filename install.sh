ufw disable

ufw allow 6443/tcp #apiserver
ufw allow from 10.42.0.0/16 to any #pods
ufw allow from 10.43.0.0/16 to any #services
set -e

curl -sfL https://get.k3s.io | sh -

sudo chmod 644 /etc/rancher/k3s/k3s.yaml

cd
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
# Show node-token (optional if you want to join other nodes)
# cat /var/lib/rancher/k3s/server/node-token