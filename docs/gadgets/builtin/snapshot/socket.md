---
title: 'Using snapshot socket'
sidebar_position: 20
description: |
  Gather information about TCP and UDP sockets.
---
:::warning

This Gadget is deprecated, please use the [snapshot_socket](../../snapshot_socket.mdx)
image-based one.

:::

The snapshot socket gadget gathers information about TCP and UDP sockets, providing visibility into network connections at the socket level.

## Use Cases

1. **Network Service Discovery**
   - Quickly identify all listening services and their associated ports across your cluster
   - Map out the network topology by understanding which services are communicating with each other

2. **Troubleshooting Network Connectivity**
   - Verify that services are binding to expected ports and addresses
   - Identify unauthorized or unexpected listening ports that might indicate security issues
   - Diagnose connection issues by checking if expected connections are in ESTABLISHED state

3. **Security Auditing**
   - Detect potentially malicious network activity by identifying unusual connection patterns
   - Verify network isolation between namespaces by checking for unexpected cross-namespace communications
   - Audit network exposure by identifying services listening on public interfaces

4. **Capacity Planning**
   - Monitor connection counts and states to understand service load patterns
   - Identify services that might need scaling based on connection metrics

5. **Compliance and Documentation**
   - Document the network behavior of applications for compliance purposes
   - Verify that network policies are correctly enforced by examining actual socket states

### On Kubernetes

#### Example 1: Basic TCP Socket Monitoring

We'll start by creating a simple nginx web server and monitor its listening sockets:

```bash
# Create a test namespace
kubectl create ns test-socketcollector

# Create an nginx pod
kubectl run nginx-app --restart=Never -n test-socketcollector --image=nginx --port=80

# Wait for the pod to be ready
kubectl wait --timeout=-1s -n test-socketcollector --for=condition=ready pod/nginx-app
kubectl get pod -n test-socketcollector
```

Now, let's check the listening sockets:

```bash
kubectl gadget snapshot socket -n test-socketcollector
```

Example output:
```
K8S.NODE            K8S.NAMESPACE       K8S.PODNAME  PROTOCOL  SRC                DST                STATUS
minikube-docker     test-socketcollector nginx-app    TCP       r/0.0.0.0:80       r/0.0.0.0:0        LISTEN
```

#### Example 2: Monitoring TCP Established Connections

Let's create a TCP client that connects to our nginx server:

```bash
# Get the nginx pod IP
NGINX_IP=$(kubectl get pod -n test-socketcollector nginx-app -o jsonpath='{.status.podIP}')

# Create a busybox pod that will connect to nginx
kubectl run client --restart=Never -n test-socketcollector --image=busybox -- /bin/sh -c "while true; do wget -qO- http://$NGINX_IP:80; sleep 5; done"

# Wait for the client pod to be ready
kubectl wait --timeout=-1s -n test-socketcollector --for=condition=ready pod/client

# Check the sockets again
kubectl gadget snapshot socket -n test-socketcollector
```

You should now see established TCP connections in the output.

#### Example 3: Monitoring UDP Sockets

Let's create a simple UDP server and client:

```bash
# Create a UDP server using netcat
kubectl create -n test-socketcollector -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: udp-server
spec:
  containers:
  - name: udp-server
    image: busybox
    command: ["sh", "-c", "nc -l -u -p 5000"]
  restartPolicy: Never
EOF

# Wait for the server to be ready
kubectl wait --timeout=-1s -n test-socketcollector --for=condition=ready pod/udp-server

# Create a client that sends UDP packets
kubectl run udp-client --restart=Never -n test-socketcollector --image=busybox -- /bin/sh -c "while true; do echo 'test' | nc -u -w 1 udp-server 5000; sleep 5; done"

# Check UDP sockets
kubectl gadget snapshot socket -n test-socketcollector --protocol udp
```

### Cleaning Up

When you're done testing, clean up the resources:

```bash
kubectl delete ns test-socketcollector
```

### With `ig`

The `snapshot socket` is not available on `ig` yet. Please check https://github.com/inspektor-gadget/inspektor-gadget/issues/744.
