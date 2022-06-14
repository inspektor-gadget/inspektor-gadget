.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager nrigadget

# eBPF objects

.PHONY: ebpf-objects
ebpf-objects:
	$(foreach dir, $(shell find ../pkg -name bpf -type d), make -C $(dir) && ) true

# Gadgets

.PHONY: gadgettracermanager
gadgettracermanager: ebpf-objects
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-tags withebpf \
		-o bin/gadgettracermanager \
		./gadgettracermanager/

# Hooks

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/ocihookgadget \
		./hooks/oci/main.go

.PHONY: nrigadget
nrigadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/nrigadget \
		./hooks/nri/main.go
