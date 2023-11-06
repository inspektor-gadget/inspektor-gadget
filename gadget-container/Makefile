.PHONY: gadget-container-deps
gadget-container-deps: entrypoint ocihookgadget gadgettracermanager nrigadget


TARGET_ARCH ?= $(shell go env GOHOSTARCH)

# Entrypoint

.PHONY: entrypoint
entrypoint:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-o bin/entrypoint \
		./entrypoint/entrypoint.go

# Gadgets

.PHONY: gadgettracermanager
gadgettracermanager:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) go build \
		-o bin/gadgettracermanager \
		./gadgettracermanager/

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
