set -e

NAMESPACE="security"

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

helm repo add infisical-helm-charts 'https://dl.cloudsmith.io/public/infisical/helm-charts/helm/charts/'
helm repo update

# Create the namespace if not exists
kubectl apply -f ./namespace.yml

echo ">>> Installing Infisical prerequisites..."
helm install --generate-name infisical-helm-charts/secrets-operator -n $NAMESPACE

echo ">>> Installing InfisicalSecert CRD..."
kubectl apply -f ./infisical/cluster-role-binding.yml -n $NAMESPACE
kubectl apply -f ./infisical/service-account.yml -n $NAMESPACE
kubectl apply -f ./infisical/service-account-reviewer.yml -n $NAMESPACE
kubectl apply -f ./infisical/secret-token-reviewer.yml -n $NAMESPACE

echo ">>> Seting up Infisical..."
kubectl patch serviceaccount infisical-token-reviewer -p '{"secrets": [{"name": "infisical-token-reviewer-token"}]}' -n $NAMESPACE
kubectl patch serviceaccount infisical-service-account -p '{"secrets": [{"name": "infisical-token-reviewer-token"}]}' -n $NAMESPACE
kubectl get secret infisical-token-reviewer-token -n $NAMESPACE -o=jsonpath='{.data.token}' | base64 --decode

echo ">>> Installing Infisical Helm chart..."
helm upgrade --install infisical infisical-helm-charts/infisical-standalone --values ./infisical/values.yml -n security