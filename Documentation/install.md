# Installation

## Installation (client side)

From the sources:
```
go get -u github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget
```

From the [releases](https://github.com/kinvolk/inspektor-gadget/releases).

## Installation (server side)

### On Lokomotive on Flatcar Edge

**Note:** You need `lokoctl` from [this branch](https://github.com/kinvolk/lokoctl/tree/alban/edge-new1)
(see discussion in [LKPR#49](https://github.com/kinvolk/lokomotive-kubernetes/pull/49)
and [PR#24](https://github.com/kinvolk/lokomotive-kubernetes/pull/24) for details).

Prepare the `lokoctl` files:

- custom.yaml:
```
# custom-units
systemd:
  units:
    - name: kubelet.service
      enable: true
      dropins:
        - name: 50-edge-cluster.conf
          contents: |
            [Service]
            Environment="KUBELET_EXTRA_ARGS=--cgroup-driver=systemd"
```

- mycluster.lokocfg:
```
variable "asset_dir" {
	type = "string"
}

variable "aws_creds" {
	type = "string"
}

variable "cluster_name" {
	type = "string"
}

variable "dns_zone" {
	type = "string"
}

variable "dns_zone_id" {
	type = "string"
}

variable "ssh_pubkey" {
	type = "string"
}


cluster "aws" {
	asset_dir = "${pathexpand(var.asset_dir)}"
	creds_path = "${pathexpand(var.aws_creds)}"
	cluster_name = "${var.cluster_name}"
	os_image = "flatcar-edge"
	dns_zone = "${var.dns_zone}"
	dns_zone_id = "${var.dns_zone_id}"
	ssh_pubkey = "${pathexpand(var.ssh_pubkey)}"

	worker_clc_snippets = ["${file("./custom.yaml")}"]
	controller_clc_snippets = ["${file("./custom.yaml")}"]
}

component "ingress-nginx" {
}
```

- lokocfg.vars:
```
cluster_name = "CHANGEME"
asset_dir = "~/lokoctl-assets/CHANGEME"
aws_creds = "~/.aws/credentials"
dns_zone = "CHANGEME"
dns_zone_id = "CHANGEME"
ssh_pubkey = "~/.ssh/id_rsa.pub"
```

Install your cluster:
```
$ lokoctl cluster install
```

Deploy the gadget daemon set:
```
$ kubectl apply -f deploy/ds-gadget.yaml
```

Finalise the installation:
```
$ ./inspektor-gadget install  # when developing you can update with --update-from-path=$PWD
$ ./inspektor-gadget health
```

### On another Kubernetes distribution

- Kubernetes
- Linux >= 4.18 (for [`bpf_get_current_cgroup_id`](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md))
- cgroup-v2 enabled in systemd, kubelet, docker, containerd and runc
- runc recompiled with [additional static OCI hooks](https://github.com/kinvolk/runc/tree/alban/static-hooks)
- tools installed on the worker nodes: [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/), [cgroupid](https://github.com/kinvolk/cgroupid), [bpftool](https://github.com/kinvolk/linux/tree/alban/bpftool-all/tools/bpf/bpftool)
- The gadget daemon set

