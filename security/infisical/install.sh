set -e

NAMESPACE="security"

helm repo add infisical-helm-charts 'https://dl.cloudsmith.io/public/infisical/helm-charts/helm/charts/'
helm repo update

# Create the namespace if not exists
kubectl apply -f /namespace.yml

echo ">>> Installing Infisical prerequisites..."
helm install --generate-name infisical-helm-charts/secrets-operator -n security

echo ">>> Installing InfisicalSecert CRD..."
kubectl apply -f /infisical/cluster-role-binding.yml -n $NAMESPACE
kubectl apply -f /infisical/service-account.yml -n $NAMESPACE
kubectl apply -f /infisical/service-account-reviewer.yml -n $NAMESPACE
kubectl apply -f /infisical/secret-token-reviewer.yml -n $NAMESPACE
kubectl apply -f /infisical/infisical-config.yml -n $NAMESPACE

echo ">>> Seting up Infisical..."
kubectl patch serviceaccount infisical-token-reviewer -p '{"secrets": [{"name": "infisical-token-reviewer-token"}]}' -n $NAMESPACE
kubectl get secret infisical-token-reviewer-token -n $NAMESPACE -o=jsonpath='{.data.token}' | base64 --decode