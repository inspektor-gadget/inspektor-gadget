---
title: 'Using advise network-policy'
weight: 20
description: >
  Generate network policies based on recorded network activity.
---

The network-policy advisor monitors the network activity in the specified
namespaces and records a summary of TCP and UDP traffic in a file. This file
can then be used to generate Kubernetes network policies.

### On Kubernetes

We will run this demo in the demo namespace:

```bash
$ kubectl create ns demo
namespace/demo created
$ kubectl apply -f docs/examples/disable-psp-demo.yaml
clusterrole.rbac.authorization.k8s.io/disable-psp-demo created
clusterrolebinding.rbac.authorization.k8s.io/disable-psp-demo created
```

In one terminal, start the network-policy gadget:

```bash
$ kubectl gadget advise network-policy monitor -n demo --output ./networktrace.log
```

In another terminal, deploy [GoogleCloudPlatform/microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo/blob/master/release/kubernetes-manifests.yaml) in the demo namespace:

```bash
$ wget -O network-policy-demo.yaml https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/c1536ff6e6782bb37e36d2e6eee0fa64a6461216/release/kubernetes-manifests.yaml
$ kubectl apply -f network-policy-demo.yaml -n demo
```

Once the demo is deployed and running correctly, we can see all the pods in the
demo namespace:

```bash
$ kubectl get pod -n demo
NAME                                     READY   STATUS    RESTARTS   AGE
adservice-6f498fc6c6-rjtrj               0/1     Running   0          28s
cartservice-bc9b949b-l8jts               0/1     Running   0          32s
checkoutservice-598d5b586d-fplr8         1/1     Running   0          36s
currencyservice-6ddbdd4956-hxkt4         1/1     Running   0          30s
emailservice-68fc78478-9g9vj             1/1     Running   0          37s
frontend-5bd77dd84b-6c5s9                1/1     Running   0          34s
loadgenerator-8f7d5d8d8-5nxw2            1/1     Running   0          31s
paymentservice-584567958d-4rp7q          1/1     Running   0          33s
productcatalogservice-75f4877bf4-xsn7m   1/1     Running   0          32s
recommendationservice-646c88579b-q9h4m   1/1     Running   0          35s
redis-cart-5b569cd47-ffqqr               1/1     Running   0          29s
shippingservice-79849ddf8-dc6st          1/1     Running   0          30s
```

At this point, let's stop the recording with Ctrl-C, and generate the
Kubernetes network policies:

```bash
$ kubectl gadget advise network-policy report --input ./networktrace.log > network-policy.yaml
```

Example for the cartservice:
* it can receive connections from the frontend and the checkoutservice
* it can initiate connections to redis-cart and make DNS queries.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: cartservice-network
  namespace: demo
spec:
  egress:
  - ports:
    - port: 6379
      protocol: TCP
    to:
    - podSelector:
        matchLabels:
          app: redis-cart
  - ports:
    - port: 53
      protocol: UDP
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: checkoutservice
    ports:
    - port: 7070
      protocol: TCP
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - port: 7070
      protocol: TCP
  podSelector:
    matchLabels:
      app: cartservice
  policyTypes:
  - Ingress
  - Egress
```

Time to apply network policies:

```bash
$ kubectl apply -f network-policy.yaml
networkpolicy.networking.k8s.io/adservice-network created
networkpolicy.networking.k8s.io/cartservice-network created
networkpolicy.networking.k8s.io/checkoutservice-network created
networkpolicy.networking.k8s.io/currencyservice-network created
networkpolicy.networking.k8s.io/emailservice-network created
networkpolicy.networking.k8s.io/frontend-network created
networkpolicy.networking.k8s.io/loadgenerator-network created
networkpolicy.networking.k8s.io/paymentservice-network created
networkpolicy.networking.k8s.io/productcatalogservice-network created
networkpolicy.networking.k8s.io/recommendationservice-network created
networkpolicy.networking.k8s.io/redis-cart-network created
networkpolicy.networking.k8s.io/shippingservice-network created
```

And redeploy the demo:

```bash
$ kubectl delete -f network-policy-demo.yaml -n demo
$ kubectl apply -f network-policy-demo.yaml -n demo
```

After a while we can see all the pods in the demo namespace:

```bash
$ kubectl get pod -n demo
NAME                                     READY   STATUS    RESTARTS   AGE
adservice-6f498fc6c6-f8sfm               1/1     Running   0          11m
cartservice-bc9b949b-7xxvr               1/1     Running   0          11m
checkoutservice-598d5b586d-59sws         1/1     Running   0          11m
currencyservice-6ddbdd4956-vdxml         1/1     Running   0          11m
emailservice-68fc78478-zxkn5             1/1     Running   0          11m
frontend-5bd77dd84b-gtcg8                1/1     Running   0          11m
loadgenerator-8f7d5d8d8-664jv            1/1     Running   0          11m
paymentservice-584567958d-ds8w6          1/1     Running   0          11m
productcatalogservice-75f4877bf4-h7654   1/1     Running   0          11m
recommendationservice-646c88579b-gvkp9   1/1     Running   0          11m
redis-cart-5b569cd47-8gwrc               1/1     Running   0          11m
shippingservice-79849ddf8-72bd4          1/1     Running   0          11m
```

Finally, we should delete the demo namespace:

```bash
$ kubectl delete namespace demo
namespace "demo" deleted
```

#### Limitations

- When using the Docker bridge as CNI, pod-to-pod source IP is lost with services. This generates wrong ingress policies. https://github.com/kubernetes/minikube/issues/11211

### With local-gadget

This gadget is specific to Kubernetes and can't be used with local-gadget.
