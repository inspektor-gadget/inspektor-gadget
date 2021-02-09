TAG := `git describe --tags --always`
VERSION :=

CONTAINER_REPO ?= docker.io/kinvolk/gadget
IMAGE_TAG=$(shell ./tools/image-tag)
IMAGE_BRANCH_TAG=$(shell ./tools/image-tag branch)

MINIKUBE ?= minikube

# Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

LDFLAGS := "-X main.version=$(VERSION) \
-X main.gadgetimage=$(CONTAINER_REPO):$(shell ./tools/image-tag branch) \
-extldflags '-static'"

.PHONY: build
build: kubectl-gadget gadget-container

# kubectl-gadget
.PHONY: kubectl-gadget
kubectl-gadget: kubectl-gadget-linux-amd64 kubectl-gadget-darwin-amd64 kubectl-gadget-windows-amd64

.PHONY: kubectl-gadget-linux-amd64
kubectl-gadget-linux-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-linux-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: kubectl-gadget-darwin-amd64
kubectl-gadget-darwin-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-darwin-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: kubectl-gadget-windows-amd64
kubectl-gadget-windows-amd64:
	GO111MODULE=on CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
		-ldflags $(LDFLAGS) \
		-o kubectl-gadget-windows-amd64 \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: install-user-linux
install-user-linux: kubectl-gadget-linux-amd64
	mkdir -p ~/.local/bin/
	cp kubectl-gadget-linux-amd64 ~/.local/bin/kubectl-gadget

# gadget container
.PHONY: gadget-container
gadget-container:
	docker build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f gadget.Dockerfile .
	docker tag $(CONTAINER_REPO):$(IMAGE_TAG) $(CONTAINER_REPO):$(IMAGE_BRANCH_TAG)

.PHONY: gadget-container-local
gadget-container-local:
	make -C gadget-container
	docker build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f gadget-local.Dockerfile .
	docker tag $(CONTAINER_REPO):$(IMAGE_TAG) $(CONTAINER_REPO):$(IMAGE_BRANCH_TAG)

.PHONY: push-gadget-container
push-gadget-container:
	docker push $(CONTAINER_REPO):$(IMAGE_TAG)
	docker push $(CONTAINER_REPO):$(IMAGE_BRANCH_TAG)

# tests
.PHONY: test
test:
	go test -test.v ./...

.PHONY: integration-tests
integration-tests:
	KUBECTL_GADGET="$(shell pwd)/kubectl-gadget-linux-amd64" \
		go test ./integration/... \
			-integration \
			-image $(CONTAINER_REPO):$(shell ./tools/image-tag branch)

# minikube
.PHONY: minikube-install
minikube-install: gadget-container-local
	kubectl patch ds -n kube-system gadget -p $$'spec:\n template:\n  spec:\n   containers:\n    - name: gadget\n      image: $(CONTAINER_REPO):$(IMAGE_TAG)\n      imagePullPolicy: Never'
	kubectl delete pod -n kube-system -l 'k8s-app=gadget'
	kubectl get pod -n kube-system -l 'k8s-app=gadget'
