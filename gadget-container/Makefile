.PHONY: gadget-container-deps
gadget-container-deps: cleanup ocihookgadget gadgettracermanager nrigadget container-hook-gatekeeper


TARGET_ARCH ?= $(shell go env GOHOSTARCH)
VERSION ?= $(shell git describe --tags --always --dirty)

.PHONY: cleanup
cleanup:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-o bin/cleanup \
		./cleanup/cleanup.go

# Gadgets

.PHONY: gadgettracermanager
gadgettracermanager:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
	 -ldflags "-X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=$(VERSION)" \
		-o bin/gadgettracermanager \
		./gadgettracermanager/

# Answers the container hook's fanotify permission events with a deadline,
# see docs/devel/container-hook-gatekeeper.md.
.PHONY: container-hook-gatekeeper
container-hook-gatekeeper:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-ldflags "-s -w" \
		-o bin/container-hook-gatekeeper \
		../cmd/container-hook-gatekeeper

# Hooks

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-o bin/ocihookgadget \
		./hooks/oci/main.go

.PHONY: nrigadget
nrigadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-o bin/nrigadget \
		./hooks/nri/main.go
