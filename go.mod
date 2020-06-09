module github.com/kinvolk/inspektor-gadget

require (
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/containerd/containerd v1.3.4 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200608131505-3aac5f0bbb5c+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0
	github.com/golang/protobuf v1.4.1
	github.com/gorilla/mux v1.7.4 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/iovisor/gobpf v0.0.0-20191129151106-ac26197bb7be
	github.com/kinvolk/traceloop v0.0.0-20200512161254-504867dad201
	github.com/kr/pretty v0.1.0
	github.com/moby/term v0.0.0-20200507201656-73f35e472e8f // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.1
	github.com/sirupsen/logrus v1.4.1
	github.com/spf13/cobra v0.0.3
	github.com/spf13/viper v1.3.2
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/weaveworks/tcptracer-bpf v0.0.0-20190731111909-cd53e7c84bac
	google.golang.org/grpc v1.27.0
	google.golang.org/protobuf v1.24.0
	gotest.tools/v3 v3.0.2 // indirect
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.17.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/cri-api v0.17.4
	sigs.k8s.io/yaml v1.1.0
)

replace github.com/iovisor/gobpf => github.com/kinvolk/gobpf v0.0.0-20191127154002-f0f89e7c6fd1

go 1.13
