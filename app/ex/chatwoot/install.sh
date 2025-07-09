set -e

NAMESPACE="app"

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

helm repo add chatwoot https://chatwoot.github.io/charts
helm repo update

helm install chatwoot chatwoot/chatwoot -f ./values.yml -n $NAMESPACE

kubectl apply -f ../ingress.yml -n $NAMESPACE