# k8s-labels-to-bpf

Deploy the daemon set:
```
kubectl apply -f deploy/ds.yaml
```

Run a tracing tool:
```
kubectl apply -f examples/ds-bcck8s.yaml
POD=$(kubectl get pods -l name=bcck8s-shell -o=jsonpath='{.items[0].metadata.name}')
kubectl exec -ti $POD -- opensnoop.sh --label role=demo
```
