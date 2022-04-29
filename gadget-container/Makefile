.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager networkpolicyadvisor nrigadget

# eBPF objects

BPF_ARCH ?= x86

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

.PHONY: networkpolicyadvisor
networkpolicyadvisor:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/networkpolicyadvisor \
		./gadgets/networkpolicyadvisor/main.go

.PHONY: networkpolicyadvisor/push
networkpolicyadvisor/push: networkpolicyadvisor
	for POD in `kubectl get pod -n gadget -l k8s-app=gadget -o=jsonpath='{.items[*].metadata.name}'` ; do kubectl cp ./bin/networkpolicyadvisor -n gadget $$POD:/bin/ ; done

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
