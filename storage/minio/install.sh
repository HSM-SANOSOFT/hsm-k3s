set -e
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
NAMESPACE="storage"

kubectl apply -f ../namespace.yml
kubectl apply -f ./manifests/infisical-secret.yml

helm repo add minio-operator https://operator.min.io
helm repo update

helm upgrade --install operator minio-operator/operator --namespace $NAMESPACE -f ./operator/values.yml

helm upgrade --install tenant minio-operator/tenant --namespace $NAMESPACE -f ./tenant/values.yml

