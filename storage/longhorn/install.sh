set -e
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
NAMESPACE="storage"

helm repo add longhorn https://charts.longhorn.io

helm repo update

helm upgrade --install longhorn longhorn/longhorn --namespace $NAMESPACE --create-namespace -f ./values.yml