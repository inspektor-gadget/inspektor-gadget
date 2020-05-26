IMAGE_TAG=$(shell ../tools/image-tag)
IMAGE_BRANCH_TAG=$(shell ../tools/image-tag branch)

MINIKUBE ?= minikube

.PHONY: gadget-container-deps
gadget-container-deps: ocihookgadget gadgettracermanager networkpolicyadvisor runchookslib

.PHONY: gadgettracermanager
gadgettracermanager:
	make -C ../pkg/gadgettracermanager/ generated-files
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/gadgettracermanager \
		./gadgettracermanager/main.go

.PHONY: ocihookgadget
ocihookgadget:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/ocihookgadget \
		./ocihookgadget/main.go

# gadgets
.PHONY: networkpolicyadvisor
networkpolicyadvisor:
	mkdir -p bin
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux go build \
		-o bin/networkpolicyadvisor \
		./gadgets/networkpolicyadvisor/main.go

.PHONY: networkpolicyadvisor/push
networkpolicyadvisor/push: networkpolicyadvisor
	for POD in `kubectl get pod -n kube-system -l k8s-app=gadget -o=jsonpath='{.items[*].metadata.name}'` ; do kubectl cp ./bin/networkpolicyadvisor -n kube-system $$POD:/bin/ ; done

.PHONY: runchookslib
runchookslib:
	mkdir -p bin
	gcc -Wall -o bin/runchooks.so -shared -fPIC runchooks/runchooks.c -ldl


.PHONY: build
build: gadget-container-deps
	docker build -t docker.io/kinvolk/gadget:$(IMAGE_TAG) -f gadget.Dockerfile .
	docker tag docker.io/kinvolk/gadget:$(IMAGE_TAG) docker.io/kinvolk/gadget:$(IMAGE_BRANCH_TAG)

.PHONY: push
push:
	docker push docker.io/kinvolk/gadget:$(IMAGE_TAG)
	docker push docker.io/kinvolk/gadget:$(IMAGE_BRANCH_TAG)

# minikube related
minikube: docker-gadget/minikube-build docker-gadget/minikube-install

docker-gadget/minikube-build:
	cp ../../traceloop/traceloop ./
	eval $(shell $(MINIKUBE) docker-env | grep =) ; docker build -t docker.io/kinvolk/gadget:minikube -f gadget-from-local-bin.Dockerfile .
	rm -f traceloop

docker-gadget/minikube-install:
	kubectl patch ds -n kube-system gadget -p $$'spec:\n template:\n  spec:\n   containers:\n    - name: gadget\n      image: docker.io/kinvolk/gadget:minikube\n      imagePullPolicy: Never'
	kubectl delete pod -n kube-system -l 'k8s-app=gadget'
	kubectl get pod -n kube-system -l 'k8s-app=gadget'
