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
build: build-slim

.PHONY: build-slim
build-slim:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build \
		-ldflags $(LDFLAGS) \
		-o inspektor-gadget \
		github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget
	cp inspektor-gadget kubectl-gadget

.PHONY: install-user
install-user: build-slim
	mkdir -p ~/.local/bin/
	cp inspektor-gadget kubectl-gadget ~/.local/bin/
