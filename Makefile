TAG := `git describe --tags --always`
VERSION :=

## Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

LDFLAGS := "-X github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget/cmd.version=$(VERSION) -extldflags '-static'"

.PHONY: build
build: build-slim

.PHONY: build-slim
build-slim:
	CGO_ENABLED=0 GOOS=linux go build \
		-ldflags $(LDFLAGS) \
		-o inspektor-gadget \
		github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget
