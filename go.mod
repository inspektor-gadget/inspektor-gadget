module github.com/kinvolk/inspektor-gadget

require (
	github.com/cilium/ebpf v0.6.2
	github.com/containerd/nri v0.1.1-0.20210619071632-28f76457b672
	github.com/docker/docker v17.12.0-ce-rc1.0.20200608131505-3aac5f0bbb5c+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0
	github.com/golang/protobuf v1.4.3
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/iovisor/gobpf v0.2.0 // indirect
	github.com/kinvolk/traceloop v0.0.0-20210623155108-6f4efc6fca46
	github.com/kr/pretty v0.2.1
	github.com/moby/term v0.0.0-20200507201656-73f35e472e8f // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.0
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/weaveworks/tcptracer-bpf v0.0.0-20200114145059-84a08fc667c0
	golang.org/x/sys v0.0.0-20210324051608-47abb6519492
	google.golang.org/grpc v1.33.2
	google.golang.org/protobuf v1.25.0
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/cli-runtime v0.20.6
	k8s.io/client-go v0.20.6
	k8s.io/cri-api v0.20.6
	sigs.k8s.io/yaml v1.2.0
)

go 1.16
