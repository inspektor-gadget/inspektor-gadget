TAG := `git describe --tags --always`
VERSION :=

CONTAINER_REPO ?= docker.io/kinvolk/gadget
IMAGE_TAG ?= $(shell ./tools/image-tag branch)

MINIKUBE ?= minikube

GOHOSTOS ?= $(shell go env GOHOSTOS)
GOHOSTARCH ?= $(shell go env GOHOSTARCH)

# Adds a '-dirty' suffix to version string if there are uncommitted changes
changes := $(shell git status --porcelain)
ifeq ($(changes),)
	VERSION := $(TAG)
else
	VERSION := $(TAG)-dirty
endif

pvpath := $(shell command -v pv 2>/dev/null || true)
ifeq ($(pvpath),)
	PV :=
else
	PV := | $(pvpath)
endif

include crd.mk
include tests.mk

LDFLAGS := "-X main.version=$(VERSION) \
-X main.gadgetimage=$(CONTAINER_REPO):$(IMAGE_TAG) \
-extldflags '-static'"

.DEFAULT_GOAL := build
.PHONY: build
build: manifests generate kubectl-gadget gadget-container

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

KUBECTL_GADGET_TARGETS = \
	kubectl-gadget-linux-amd64 \
	kubectl-gadget-linux-arm64 \
	kubectl-gadget-darwin-amd64 \
	kubectl-gadget-darwin-arm64 \
	kubectl-gadget-windows-amd64

.PHONY: list-kubectl-gadget-targets
list-kubectl-gadget-targets:
	@echo $(KUBECTL_GADGET_TARGETS)

.PHONY: kubectl-gadget-all
kubectl-gadget-all: $(KUBECTL_GADGET_TARGETS)

kubectl-gadget: kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH)
	mv kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH) kubectl-gadget

kubectl-gadget-%: phony_explicit
	export GO111MODULE=on CGO_ENABLED=0 && \
	export GOOS=$(shell echo $* |cut -f1 -d-) GOARCH=$(shell echo $* |cut -f2 -d-) && \
	go build -ldflags $(LDFLAGS) \
		-o kubectl-gadget-$${GOOS}-$${GOARCH} \
		github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget

.PHONY: install/kubectl-gadget
install/kubectl-gadget: kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH)
	mkdir -p ~/.local/bin/
	cp kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH) ~/.local/bin/kubectl-gadget

# gadget container
.PHONY: gadget-container
gadget-container:
	docker build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f gadget.Dockerfile .

.PHONY: push-gadget-container
push-gadget-container:
	docker push $(CONTAINER_REPO):$(IMAGE_TAG)

# tests
.PHONY: test
test:
	go test -test.v ./...

.PHONY: controller-tests
controller-tests: kube-apiserver etcd kubectl
	ACK_GINKGO_DEPRECATIONS=1.16.4 \
	TEST_ASSET_KUBE_APISERVER=$(KUBE_APISERVER_BIN) \
	TEST_ASSET_ETCD=$(ETCD_BIN) \
	TEST_ASSET_KUBECTL=$(KUBECTL_BIN) \
	go test -test.v ./pkg/controllers/... -controller-test

.PHONY: integration-tests
integration-tests: kubectl-gadget
	KUBECTL_GADGET="$(shell pwd)/kubectl-gadget" \
		go test ./integration/... \
			-integration \
			-image $(CONTAINER_REPO):$(IMAGE_TAG)

.PHONY: generate-documentation
generate-documentation:
	go run -tags docs cmd/gen-doc/gen-doc.go -repo $(shell pwd)

# minikube
LIVENESS_PROBE_INITIAL_DELAY_SECONDS ?= 10
.PHONY: minikube-install
minikube-install: gadget-container kubectl-gadget
	# Unfortunately, minikube-cache and minikube-image have bugs in older
	# versions. And new versions of minikube don't support all eBPF
	# features. So we have to keep "docker-save|docker-load" for now.
	docker save $(CONTAINER_REPO):$(IMAGE_TAG) $(PV) | (eval $(shell $(MINIKUBE) -p minikube docker-env | grep =) && docker load)
	# Delete traces CRD first: the gadget DaemonSet needs to be running
	# because of Finalizers.
	kubectl delete crd traces.gadget.kinvolk.io || true
	./kubectl-gadget deploy | kubectl delete -f - || true
	time kubectl wait --for=delete namespace gadget 2>/dev/null || true
	time kubectl wait --for=delete daemonset -n kube-system gadget 2>/dev/null || true
	./kubectl-gadget deploy --traceloop=false --hook-mode=fanotify | \
		sed 's/imagePullPolicy: Always/imagePullPolicy: Never/g' | \
		sed 's/initialDelaySeconds: 10/initialDelaySeconds: '$(LIVENESS_PROBE_INITIAL_DELAY_SECONDS)'/g' | \
		kubectl apply -f -
