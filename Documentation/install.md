# Installation

## Installation (client side)

Choose one way to install inspektor-gadget.

### Quick installation

```
$ curl -s -L --output inspektor-gadget.zip https://github.com/kinvolk/inspektor-gadget/suites/333471026/artifacts/477863
$ unzip inspektor-gadget.zip
$ chmod +x inspektor-gadget/inspektor-gadget
$ sudo cp inspektor-gadget/inspektor-gadget /usr/local/bin/kubectl-gadget
```

Check installation:

```
$ inspektor-gadget version
v0.1.0-alpha.2-12-gb9fd574
```

### From a release

Follow instructions from the [releases](https://github.com/kinvolk/inspektor-gadget/releases).

### From a specific branch and commit

* Go to the [GitHub Actions page](https://github.com/kinvolk/inspektor-gadget/actions)
* Select one successful build from the desired branch and commit
* Download inspektor-gadget.zip:
  ![Download artifacts](github-actions-download-artifacts.png)
* Finish the installation:
```
$ unzip inspektor-gadget.zip
$ chmod +x inspektor-gadget/inspektor-gadget
$ sudo cp inspektor-gadget/inspektor-gadget /usr/local/bin/kubectl-gadget
```

### From the sources:

```
$ git clone https://github.com/kinvolk/inspektor-gadget.git
$ cd inspektor-gadget
$ make
```

Note:
- if you wish to make changes to traceloop program, update `gadget-ds/gadget.Dockerfile` to pick your own image of traceloop.
- if you wish to make other changes in the gadget container image, update `Makefile` to choose the default `gadgetimage`.

See the [minikube](#Development-environment-on-minikube-for-the-traceloop-gadget) section for a faster development cycle.


## Installation (server side)

### Quick installation

```
$ inspektor-gadget deploy | kubectl apply -f -
```

This will deploy the gadget DaemonSet along with its RBAC rules.

### Choosing the gadget image

If you wish to install an alternative gadget image, you could use the following commands:

```
$ inspektor-gadget deploy --image=docker.io/myfork/gadget:tag | kubectl apply -f -
```

## Getting all gadgets

Not all gadgets currently work everywhere.

| Gadget            | Flatcar Edge | Flatcar Stable | Minikube | GKE |
|-------------------|:------------:|:--------------:|:--------:|:---:|
| traceloop         |       ✔️      |        ✔️       |     ✔️    |  ✔️  |
| network-policy    |       ✔️      |        ✔️       |     ✔️    |  ✔️  |
| tcptracer         |       ✔️      |                |          |     |
| tcpconnect        |       ✔️      |                |          |     |
| tcptop            |       ✔️      |                |          |     |
| execsnoop         |       ✔️      |                |          |     |
| opensnoop         |       ✔️      |                |          |     |
| bindsnoop         |       ✔️      |                |          |     |
| capabilities      |       ✔️      |                |          |     |
| profile           |       ✔️      |                |          |     |

Inspektor Gadget needs some recent Linux features and modifications in Kubernetes present in [Flatcar Container Linux Edge](https://kinvolk.io/blog/2019/05/introducing-the-flatcar-linux-edge-channel/) and [Lokomotive](https://kinvolk.io/blog/2019/05/driving-kubernetes-forward-with-lokomotive/).

### Using Lokomotive on Flatcar Edge

Install your cluster following the [Lokomotive docs for AWS](https://github.com/kinvolk/lokomotive-kubernetes/blob/master/docs/flatcar-linux/aws.md)
or [for KVM with libvirt](https://github.com/kinvolk/lokomotive-kubernetes/blob/master/docs/flatcar-linux/kvm-libvirt.md).

Note, you should enable Flatcar Container Linux edge following the [Lokomotive docs](https://github.com/kinvolk/lokomotive-kubernetes/#try-flatcar-edge).

### On another Kubernetes distribution

If you wish to install all the gadgets on another Kubernetes distribution, you will need the following:

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
- The gadget daemon set

## Development environment on minikube for the traceloop gadget

It's possible to make changes to traceloop and test them on minikube locally without pushing container images to any registry.

* Make sure the git repositories `traceloop` and `inspektor-gadget` are clone in sibling directories
* Install Inspektor Gadget on minikube as usual:
```
$ inspektor-gadget deploy | kubectl apply -f -
```
* Make changes in the traceloop repository and compile with `make`
* Generate the new gadget image and deploy it to minikube:
```
$ make -C gadget-ds/ minikube
```

Note that the minikube image only works with the traceloop gadget.
