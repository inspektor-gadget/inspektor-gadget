module github.com/kinvolk/inspektor-gadget

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/cilium/ebpf v0.8.2-0.20220329140945-23f447c3cb0c
	github.com/containerd/containerd v1.5.11 // indirect
	github.com/containerd/nri v0.1.1-0.20210619071632-28f76457b672
	github.com/containers/common v0.46.0
	github.com/docker/distribution v2.8.0+incompatible // indirect
	github.com/docker/docker v20.10.8+incompatible
	github.com/docker/go-units v0.4.0
	github.com/giantswarm/crd-docs-generator v0.7.1
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/iovisor/gobpf v0.2.0 // indirect
	github.com/kinvolk/traceloop v0.0.0-20210623155108-6f4efc6fca46
	github.com/kr/pretty v0.3.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.16.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/prometheus/client_golang v1.11.0
	github.com/s3rj1k/go-fanotify/fanotify v0.0.0-20210917134616-9c00a300bb7a
	github.com/seccomp/libseccomp-golang v0.9.2-0.20200616122406-847368b35ebf
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f
	github.com/weaveworks/tcptracer-bpf v0.0.0-20200114145059-84a08fc667c0
	golang.org/x/sys v0.0.0-20220307203707-22a9840ba4d7
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/grpc v1.42.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.22.3
	k8s.io/apiextensions-apiserver v0.22.3
	k8s.io/apimachinery v0.22.3
	k8s.io/cli-runtime v0.21.0
	k8s.io/client-go v0.22.3
	k8s.io/code-generator v0.22.3
	k8s.io/cri-api v0.20.6
	sigs.k8s.io/controller-runtime v0.10.3
	sigs.k8s.io/security-profiles-operator v0.3.1-0.20211122222133-6e12fe5f2daa
	sigs.k8s.io/yaml v1.2.0
)

go 1.16

// avoid reports on CVE-2021-3121
replace (
	github.com/gogo/protobuf v1.1.1 => github.com/gogo/protobuf v1.3.2
	github.com/gogo/protobuf v1.2.1 => github.com/gogo/protobuf v1.3.2
	github.com/gogo/protobuf v1.3.0 => github.com/gogo/protobuf v1.3.2
	github.com/gogo/protobuf v1.3.1 => github.com/gogo/protobuf v1.3.2
)
