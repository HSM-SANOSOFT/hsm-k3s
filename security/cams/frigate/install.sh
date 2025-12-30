kubectl  -n security delete configmap hsm-security-cams-frigate-configmap
kubectl -n security create configmap hsm-security-cams-frigate-configmap --from-file=config.yml=/home/sanosoft/hsm-k3s/security/cams/frigate/config.yml
kubectl -n security rollout restart deploy/hsm-security-cams-frigate
POD=$(kubectl -n security get pod -l app=hsm-security-cams-frigate -o jsonpath='{.items[0].metadata.name}')
echo "To view logs:"
echo "  kubectl -n security logs -f $POD"
echo "To search for the admin reset password in logs:"
echo "  kubectl -n security logs $POD | grep -iE 'password|admin|reset'"
echo "  kubectl -n security logs -f $POD | grep -iE 'password|admin|reset'"
kubectl -n security get pod -l app=hsm-security-cams-frigate -w