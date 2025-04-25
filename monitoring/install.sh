set -e

NAMESPACE="monitoring"
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Create the namespace if not exists
kubectl apply -f ./namespace.yml
kubectl apply -f ./ingress.yml

echo ">>> Installing Loki..."
helm upgrade --install loki grafana/loki -n $NAMESPACE -f ./loki/values.yml

echo ">>> Installing Promtail prerequisites..."
kubectl apply -f ./promtail/cluster-role.yml -n $NAMESPACE
kubectl apply -f ./promtail/cluster-role-binding.yml -n $NAMESPACE
kubectl apply -f ./promtail/service-account.yml -n $NAMESPACE
kubectl apply -f ./promtail/configmap.yml -n $NAMESPACE

echo ">>> Installing Promtail..."
helm upgrade --install promtail grafana/promtail -n $NAMESPACE -f ./promtail/values.yml

echo ">>> Installing Mimir..."
helm upgrade --install mimir grafana/mimir-distributed -n $NAMESPACE -f ./mimir/values.yml

echo ">>> Installing kube-state-metrics..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-state-metrics prometheus-community/kube-state-metrics -n $NAMESPACE

echo ">>> Installing Tempo..."

echo ">>> Installing Grafana ConfigMap..."
kubectl apply -f ./grafana/configmap.yml -n $NAMESPACE

echo ">>> Installing Grafana..."
helm upgrade --install grafana grafana/grafana -n $NAMESPACE -f ./grafana/values.yml