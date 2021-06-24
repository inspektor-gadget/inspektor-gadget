.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager networkpolicyadvisor runchookslib nrigadget

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
