.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager nrigadget


TARGET_ARCH ?= $(shell go env GOHOSTARCH)

ifdef DEBUG
# We need this flag to help debugging with delve:
# -N: disable optimization.
# -l: disable inlining.
# (see https://pkg.go.dev/cmd/compile)
CFLAGS = -gcflags="all=-N -l"
endif

# Gadgets

.PHONY: gadgettracermanager
gadgettracermanager:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-tags withebpf \
		$(CFLAGS) \
		-o bin/gadgettracermanager \
		./gadgettracermanager/

# Hooks

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		$(CFLAGS) \
		-o bin/ocihookgadget \
		./hooks/oci/main.go

.PHONY: nrigadget
nrigadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		$(CFLAGS) \
		-o bin/nrigadget \
		./hooks/nri/main.go
