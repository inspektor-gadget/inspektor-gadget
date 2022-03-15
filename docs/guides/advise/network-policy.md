---
title: 'Using advise network-policy'
weight: 20
description: >
  Generate network policies based on recorded network activity.
---

The network-policy advisor monitors the network activity in the specified namespaces and
records the list of new TCP connections in a file. This file can then be used to
generate Kubernetes network policies.

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
$ kubectl gadget advise network-policy monitor --namespaces demo --output ./networktrace.log
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
adservice-77d5cd745d-vkwzp               0/1     Running   0          30s
cartservice-74f56fd4b-ghqx8              0/1     Running   0          31s
checkoutservice-69c8ff664b-zvdw4         0/1     Running   0          32s
currencyservice-77654bbbdd-drpvw         0/1     Running   0          31s
emailservice-54c7c5d9d-95qhl             1/1     Running   0          32s
frontend-99684f7f8-28k6c                 1/1     Running   0          32s
loadgenerator-555fbdc87d-b9vwv           1/1     Running   0          31s
paymentservice-bbcbdc6b6-lg4rh           0/1     Running   0          32s
productcatalogservice-68765d49b6-nntph   0/1     Running   0          32s
recommendationservice-5f8c456796-dcgpw   1/1     Running   0          32s
redis-cart-78746d49dc-4nq5j              1/1     Running   0          30s
shippingservice-5bd985c46d-25kjl         1/1     Running   0          31s
```

At this point, let's stop the recording with Ctrl-C, and generate the
Kubernetes network policies:

```bash
$ kubectl gadget advise network-policy report --input ./networktrace.log > network-policy.yaml
```

Example for the cartservice: it can receive connections from the frontend and can initiate connections to redis-cart.

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

```bash
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

```bash
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

```bash
$ kubectl delete namespace demo
namespace "demo" deleted
```

### With local-gadget

* Start local-gadget:

```bash
$ sudo ./local-gadget --runtimes=docker
» create network-graph trace1 --container-selector demo
State: Started
» stream trace1 -f
```

* Generate some network traffic:

```bash
> $ docker run --name demo -ti --rm busybox
> / # wget http://1.1.1.1.nip.io/
```

* Observe the results:

```json
{"type":"debug","message":"tracer attached","node":"local","namespace":"default","pod":"demo"}
{"type":"normal","namespace":"default","pod":"demo","pkt_type":"OUTGOING","proto":"tcp","ip":"1.1.1.1","port":80}
{"type":"normal","namespace":"default","pod":"demo","pkt_type":"OUTGOING","proto":"udp","ip":"192.168.0.1","port":53}
```
