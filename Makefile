TAG := `git describe --tags --always`
VERSION :=

## Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

LDFLAGS := "-X github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget/cmd.version=$(VERSION) -X github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget/cmd.gadgetimage=docker.io/kinvolk/gadget:$(shell ./tools/image-tag branch) -extldflags '-static'"

.PHONY: build
build: gadget-container-deps build-ig

.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager networkpolicyadvisor

.PHONY: build-ig
build-ig:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build \
		-ldflags $(LDFLAGS) \
		-o inspektor-gadget \
		github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget
	cp inspektor-gadget kubectl-gadget

.PHONY: gadgettracermanager
gadgettracermanager:
	make -C pkg/gadgettracermanager/ generated-files
	mkdir -p gadget-ds/bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o gadget-ds/bin/gadgettracermanager \
		cmd/gadgettracermanager/main.go

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p gadget-ds/bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o gadget-ds/bin/ocihookgadget \
		cmd/ocihookgadget/main.go

.PHONY: networkpolicyadvisor
networkpolicyadvisor:
	mkdir -p gadget-ds/bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o gadget-ds/bin/networkpolicyadvisor \
		cmd/networkpolicyadvisor/main.go

.PHONY: networkpolicyadvisor/push
networkpolicyadvisor/push: networkpolicyadvisor
	for POD in `kubectl get pod -n kube-system -l k8s-app=gadget -o=jsonpath='{.items[*].metadata.name}'` ; do kubectl cp ./gadget-ds/bin/networkpolicyadvisor -n kube-system $$POD:/bin/ ; done

.PHONY: install-user
install-user: build-ig
	mkdir -p ~/.local/bin/
	cp inspektor-gadget kubectl-gadget ~/.local/bin/
