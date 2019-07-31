# Installation

## Installation (client side)

From the sources:
```
go get -u github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget
```

From the [releases](https://github.com/kinvolk/inspektor-gadget/releases).

## Installation (server side)

### On Lokomotive on Flatcar Edge

Install your cluster following the [Lokomotive docs for AWS](https://github.com/kinvolk/lokomotive-kubernetes/blob/master/docs/flatcar-linux/aws.md)
or [for KVM with libvirt](https://github.com/kinvolk/lokomotive-kubernetes/blob/master/docs/flatcar-linux/kvm-libvirt.md).

Note, you should enable Flatcar Linux edge following the [Lokomotive docs](https://github.com/kinvolk/lokomotive-kubernetes/#try-flatcar-edge).

Deploy the gadget daemon set:
```
$ kubectl apply -f deploy/ds-gadget.yaml
```

Check the installation (run this multiple times to see if the pods are ready):
```
$ ./inspektor-gadget health
```

(Development note: Use `$ ./inspektor-gadget install --update-from-path=$PWD` to deploy changed binaries.)

### On another Kubernetes distribution

- Kubernetes
- Linux >= 4.18 (for [`bpf_get_current_cgroup_id`](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md))
- cgroup-v2 enabled in:
  - systemd
    - boot option `systemd.unified_cgroup_hierarchy=false systemd.legacy_systemd_cgroup_controller=false`
  - kubelet
    - `--cgroup-driver=systemd`
  - docker
    - `DOCKER_OPTS="--exec-opt native.cgroupdriver=systemd"`
  - containerd
    - `systemd_cgroup = true` in `$XDG_DATA_DIR/share/containerd/config.toml`
  - runc
- runc recompiled with [additional static OCI hooks](https://github.com/kinvolk/runc/tree/alban/static-hooks)
- tools installed in `/opt/bin` on the nodes: [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/), [cgroupid](https://github.com/kinvolk/cgroupid), [bpftool](https://github.com/kinvolk/linux/tree/alban/bpftool-all/tools/bpf/bpftool)
- The gadget daemon set

