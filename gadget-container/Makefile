.PHONY: gadget-container-deps
gadget-container-deps: dns collector-process ocihookgadget gadgettracermanager networkpolicyadvisor runchookslib nrigadget

CLANG_OS_FLAGS = ""
ifeq ($(shell grep -oP '^NAME="\K\w+(?=")' /etc/os-release), Ubuntu)
	CLANG_OS_FLAGS="-I/usr/include/$(shell uname -m)-linux-gnu"
endif

# eBPF objects

.PHONY: ebpf-objects
ebpf-objects: \
		gadgets/collector-process/bpf/collector-process.o \
		gadgets/collector-process/bpf/collector-process-with-filter.o \
		gadgets/dns/bpf/dns.o

gadgets/collector-process/bpf/collector-process.o: gadgets/collector-process/bpf/collector-process.c
	clang $(CLANG_OS_FLAGS) -target bpf -O2 -g -c -x c $< -o $@

gadgets/collector-process/bpf/collector-process-with-filter.o: gadgets/collector-process/bpf/collector-process.c
	clang $(CLANG_OS_FLAGS) -target bpf -O2 -g -c -x c $< -o $@ -DWITH_FILTER=1

gadgets/dns/bpf/dns.o: gadgets/dns/bpf/dns.c
	clang $(CLANG_OS_FLAGS) -target bpf -O2 -g -c -x c $< -o $@

# Gadgets

.PHONY: gadgettracermanager
gadgettracermanager:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/gadgettracermanager \
		./gadgettracermanager/main.go

.PHONY: networkpolicyadvisor
networkpolicyadvisor:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/networkpolicyadvisor \
		./gadgets/networkpolicyadvisor/main.go

.PHONY: collector-process
collector-process: gadgets/collector-process/bpf/collector-process.o gadgets/collector-process/bpf/collector-process-with-filter.o
	go build -tags withebpf -o bin/collector-process ./gadgets/collector-process/

.PHONY: dns
dns: gadgets/dns/bpf/dns.o
	go build -tags withebpf -o bin/dns ./gadgets/dns/

.PHONY: networkpolicyadvisor/push
networkpolicyadvisor/push: networkpolicyadvisor
	for POD in `kubectl get pod -n kube-system -l k8s-app=gadget -o=jsonpath='{.items[*].metadata.name}'` ; do kubectl cp ./bin/networkpolicyadvisor -n kube-system $$POD:/bin/ ; done

# Hooks

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/ocihookgadget \
		./hooks/oci/main.go

.PHONY: runchookslib
runchookslib:
	mkdir -p bin
	gcc -Wall -o bin/runchooks.so -shared -fPIC hooks/runc/runchooks.c -ldl

.PHONY: nrigadget
nrigadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/nrigadget \
		./hooks/nri/main.go
