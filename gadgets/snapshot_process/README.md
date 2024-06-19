> ⚠️ This feature is experimental and could change without prior notification. Check the installation guide to enable [experimental features](../../docs/getting-started/install-linux.md#experimental-features).

The snapshot process gadget gathers information about running processes.

### On Kubernetes

Let's start this demo by creating a namespace:

```bash
$ kubectl create ns demo
namespace/demo created
```

There is not any running process in the `demo` namespace now:

```bash
$ kubectl gadget run snapshot_process -n demo
K8S.NODE            K8S.NAMESPACE       K8S.POD             K8S.CONTAINER       COMM       PID       TID       PPID       UID       GID
```

Create a pod on the `demo` namespace using the `nginx` image:

```bash
$ kubectl -n demo run mypod --image=nginx
pod/mypod created
$ kubectl wait -n demo --for=condition=ready pod/mypod
pod/mypod condition met
```

After the pod is running, we can try to get the list of running processes again:

```bash
$ kubectl gadget run snapshot_process -n demo
INFO[0000] Experimental features enabled
K8S.NODE            K8S.NAMESPACE       K8S.POD             K8S.CONTAINER       COMM       PID       TID       PPID      UID       GID
ubuntu-hirsute      demo                mypod               mypod               nginx      411928    411928    411902    0         0
ubuntu-hirsute      demo                mypod               mypod               nginx      411964    411964    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411965    411965    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411966    411966    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411967    411967    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411968    411968    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411969    411969    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411970    411970    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411971    411971    411928    101       101
```

We can see the different `nginx` process started within the container.

Execute an instance of `sleep` on the pod:

```bash
$ kubectl -n demo exec mypod -- /bin/sh -c "sleep 1000 &"
```

Now there is an additional `sleep` processes running in `mypod`:

```bash
$ kubectl gadget run snapshot_process -n demo
INFO[0000] Experimental features enabled
K8S.NODE            K8S.NAMESPACE       K8S.POD             K8S.CONTAINER       COMM       PID       TID       PPID      UID       GID
ubuntu-hirsute      demo                mypod               mypod               nginx      411928    411928    411902    0         0
ubuntu-hirsute      demo                mypod               mypod               nginx      411964    411964    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411965    411965    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411966    411966    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411967    411967    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411968    411968    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411969    411969    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411970    411970    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               nginx      411971    411971    411928    101       101
ubuntu-hirsute      demo                mypod               mypod               sleep      412000    412000    411928    0         0
```

Delete the demo test namespace:

```bash
$ kubectl delete ns demo
namespace "demo" deleted
```

### With `ig`

Create a container that runs sleep inside:

```bash
$ docker run --name test-snapshot-process -it --rm busybox /bin/sh -c 'sleep 100'
```

Run the snapshot process gadget, it'll print all process in the container:

```bash
$ sudo ig snapshot process -c test-snapshot-process
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME            MNTNS_ID           PID            TID             PPID           UID        GID      COMM     NETNS                  
test-snapshot-process            4026533169         2666921        2666921         2666899        0          0        sh       0  
```
