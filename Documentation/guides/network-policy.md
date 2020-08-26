---
title: 'The "network-policy" gadget'
weight: 10
---

network-policy monitors the network activity in the specified namespaces and
record the list of new TCP connections in a file. This file can then be used to
generate Kubernetes network policies.

We will run this demo in the demo namespace:

```
$ kubectl create ns demo
namespace/demo created
$ kubectl apply -f Documentation/examples/disable-psp-demo.yaml
clusterrole.rbac.authorization.k8s.io/disable-psp-demo created
clusterrolebinding.rbac.authorization.k8s.io/disable-psp-demo created
```

In one terminal, start the network-policy gadget:

```
$ kubectl gadget network-policy monitor --namespaces demo --output ./networktrace.log
```

In another terminal, deploy [GoogleCloudPlatform/microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo/blob/master/release/kubernetes-manifests.yaml) in the demo namespace:
```
$ wget -O network-policy-demo.yaml https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/ccff406cdcd3e043b432fe99b4038d1b4699c702/release/kubernetes-manifests.yaml
$ kubectl apply -f network-policy-demo.yaml -n demo
```

Once the demo is deployed and running correctly, we can see all the pods in the
demo namespace:

```
$ kubectl get pod -n demo
NAME                                     READY   STATUS    RESTARTS   AGE
adservice-58c85c77d8-k5667               1/1     Running   0          44s
cartservice-579bdd6865-2wcbk             0/1     Running   1          45s
checkoutservice-66d68cbdd-smp6w          1/1     Running   0          46s
currencyservice-65dd85f486-62vld         1/1     Running   0          45s
emailservice-84c98657cb-lqwfz            0/1     Running   2          46s
frontend-788f7bdc86-q56rw                0/1     Running   1          46s
loadgenerator-7699dc7d4b-j6vq6           1/1     Running   1          45s
paymentservice-5c54c9887b-prz7n          1/1     Running   0          45s
productcatalogservice-7df777f796-29lmz   1/1     Running   0          45s
recommendationservice-89547cff8-xf4mv    0/1     Running   1          46s
redis-cart-5f59546cdd-6rq8f              0/1     Running   2          44s
shippingservice-778db496dd-mhdk5         1/1     Running   0          45s
```

At this point, let's stop the recording with Ctrl-C, and generate the
Kubernetes network policies:

```
$ kubectl gadget network-policy report --input ./networktrace.log > network-policy.yaml
```

Example for the cartservice: it can receive connections from the frontend and can initiate connections to redis-cart.

```
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
  ingress:
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

```
$ kubectl apply -f network-policy.yaml
networkpolicy.networking.k8s.io/cartservice-network created
networkpolicy.networking.k8s.io/checkoutservice-network created
networkpolicy.networking.k8s.io/currencyservice-network created
networkpolicy.networking.k8s.io/frontend-network created
networkpolicy.networking.k8s.io/productcatalogservice-network created
networkpolicy.networking.k8s.io/redis-cart-network created
networkpolicy.networking.k8s.io/shippingservice-network created
```

After a while we can see all the pods in the demo namespace:

```
$kubectl get pod -n demo
NAME                                     READY   STATUS             RESTARTS   AGE
adservice-58c85c77d8-k5667               1/1     Running            0          5m11s
cartservice-579bdd6865-2wcbk             1/1     Running            0          5m12s
checkoutservice-66d68cbdd-smp6w          1/1     Running            0          5m14s
currencyservice-65dd85f486-62vld         1/1     Running            0          5m12s
emailservice-84c98657cb-lqwfz            0/1     Running            5          5m14s
frontend-788f7bdc86-q56rw                1/1     Running            0          5m13s
loadgenerator-7699dc7d4b-j6vq6           1/1     Running            2          5m12s
paymentservice-5c54c9887b-prz7n          1/1     Running            0          5m13s
productcatalogservice-7df777f796-29lmz   1/1     Running            0          5m13s
recommendationservice-89547cff8-xf4mv    0/1     Running            4          5m14s
redis-cart-5f59546cdd-6rq8f              1/1     Running            0          5m11s
shippingservice-778db496dd-mhdk5         1/1     Running            0          5m12s
```

(`emailservice-84c98657cb-lqwfz` and `recommendationservice-89547cff8-xf4mv` services are failing because `GOOGLE_APPLICATION_CREDENTIALS` are not set)

Finally, we should delete the demo namespace:

```
$ kubectl delete namespace demo
namespace "demo" deleted
```
