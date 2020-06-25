TAG := `git describe --tags --always`
VERSION :=
CONTAINER_REPO ?= docker.io/kinvolk/gadget

## Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

LDFLAGS := "-X main.version=$(VERSION) \
-X main.gadgetimage=$(CONTAINER_REPO):$(shell ./tools/image-tag branch) \
-extldflags '-static'"

.PHONY: build
build: kubectl-gadget build-gadget-container

.PHONY: kubectl-gadget
kubectl-gadget: kubectl-gadget-linux-amd64 kubectl-gadget-darwin-amd64

.PHONY: kubectl-gadget-linux-amd64
kubectl-gadget-linux-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-linux-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: kubectl-gadget-darwin-amd64
kubectl-gadget-darwin-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-darwin-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: install-user-linux
install-user-linux: kubectl-gadget-linux-amd64
	mkdir -p ~/.local/bin/
	cp kubectl-gadget-linux-amd64 ~/.local/bin/kubectl-gadget

.PHONY: build-gadget-container
build-gadget-container:
	make -C gadget-container build

.PHONY: test
test:
	go test -test.v ./...

.PHONY: integration-tests
integration-tests:
	KUBECTL_GADGET="$(shell pwd)/kubectl-gadget-linux-amd64" \
		go test ./integration/... \
			-integration \
			-image $(CONTAINER_REPO):$(shell ./tools/image-tag branch)
