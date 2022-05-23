# Example with the container-collection package

This example uses the container-collection package
("github.com/kinvolk/inspektor-gadget/pkg/container-collection") in order to be
notified when a new container is started and to attach the OCI config.json as a
Kubernetes event.

This uses a DaemonSet: each pod will only monitor containers locally.

To deploy the DaemonSet:
```
$ make install
```

Start a new pod:
```
$ kubectl run -ti --rm --image busybox shell1 -- sh
```

Notice the new event:
```
$ kubectl get events
LAST SEEN   TYPE     REASON               OBJECT       MESSAGE
7s          Normal   Scheduled            pod/shell1   Successfully assigned default/shell1 to minikube
6s          Normal   Pulling              pod/shell1   Pulling image "busybox"
5s          Normal   Pulled               pod/shell1   Successfully pulled image "busybox" in 1.675873757s
5s          Normal   Created              pod/shell1   Created container shell1
4s          Normal   NewContainerConfig   pod/shell1   {"ociVersion":"1.0.2-dev",...}
4s          Normal   Started              pod/shell1   Started container shell1

```

This can also be seen with the following command:
```
$ kubectl describe pod shell1
Name:         shell1
Namespace:    default
...
Events:
  Type    Reason              Age   From                     Message
  ----    ------              ----  ----                     -------
  Normal  Scheduled           60s   default-scheduler        Successfully assigned default/shell1 to minikube
  Normal  Pulling             59s   kubelet                  Pulling image "busybox"
  Normal  Pulled              58s   kubelet                  Successfully pulled image "busybox" in 1.675873757s
  Normal  Created             58s   kubelet                  Created container shell1
  Normal  NewContainerConfig  57s   KubeContainerCollection  {"ociVersion":"1.0.2-dev",...}
  Normal  Started             57s   kubelet                  Started container shell1

```
