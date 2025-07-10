
kubectl apply -f ./IPAddressPool.yml
kubectl apply -f ./L2Advertisement.yml
kubectl apply -f ./manifest.yml

kubectl -n kube-system patch svc traefik   --type merge   -p '{"spec":{"type":"LoadBalancer"}}'