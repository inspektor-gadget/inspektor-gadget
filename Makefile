TAG := `git describe --tags --always`
VERSION :=

CONTAINER_REPO ?= ghcr.io/kinvolk/inspektor-gadget
IMAGE_TAG ?= $(shell ./tools/image-tag branch)

MINIKUBE ?= minikube
KUBERNETES_DISTRIBUTION ?= ""

GOHOSTOS ?= $(shell go env GOHOSTOS)
GOHOSTARCH ?= $(shell go env GOHOSTARCH)

ENABLE_BTFGEN ?= false

BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

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

# export variables that are used in Makefile.btfgen as well.
export BPFTOOL ARCH

include crd.mk
include tests.mk

LDFLAGS := "-X main.version=$(VERSION) \
-X main.gadgetimage=$(CONTAINER_REPO):$(IMAGE_TAG) \
-extldflags '-static'"

.DEFAULT_GOAL := build
.PHONY: build
build: manifests generate kubectl-gadget gadget-default-container

.PHONY: all
all: build local-gadget

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

ebpf-objects:
	docker run --rm --name ebpf-object-builder --user $(shell id -u):$(shell id -g) -v $(shell pwd):/work ghcr.io/kinvolk/inspektor-gadget-ebpf-builder

epbf-objects-outside-docker:
	TARGET=arm64 go generate ./...
	TARGET=amd64 go generate ./...

# local-gadget

LOCAL_GADGET_TARGETS = \
	local-gadget-linux-amd64 \
	local-gadget-linux-arm64

.PHONY: list-local-gadget-targets
list-local-gadget-targets:
	@echo $(LOCAL_GADGET_TARGETS)

.PHONY: local-gadget-all
local-gadget-all: $(LOCAL_GADGET_TARGETS) local-gadget

local-gadget: local-gadget-$(GOHOSTOS)-$(GOHOSTARCH)
	cp local-gadget-$(GOHOSTOS)-$(GOHOSTARCH) local-gadget

local-gadget-%: phony_explicit
	echo Building local-gadget-$* && \
	export GOOS=$(shell echo $* |cut -f1 -d-) GOARCH=$(shell echo $* |cut -f2 -d-) && \
	docker buildx build -t local-gadget-$*-builder -f Dockerfiles/local-gadget.Dockerfile \
		--build-arg GOOS=$${GOOS} --build-arg GOARCH=$${GOARCH} --build-arg VERSION=$(VERSION) . && \
	docker run --rm --entrypoint cat local-gadget-$*-builder local-gadget-$* > local-gadget-$* && \
	chmod +x local-gadget-$*

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
kubectl-gadget-all: $(KUBECTL_GADGET_TARGETS) kubectl-gadget

kubectl-gadget: kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH)
	cp kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH) kubectl-gadget

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

# gadget BCC container image
.PHONY: gadget-default-container
gadget-default-container:
	docker buildx build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f Dockerfiles/gadget-default.Dockerfile \
		--build-arg ENABLE_BTFGEN=$(ENABLE_BTFGEN) .

# gadget CO-RE container image
.PHONY: gadget-core-container
gadget-core-container:
	docker buildx build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f Dockerfiles/gadget-core.Dockerfile \
		--build-arg ENABLE_BTFGEN=$(ENABLE_BTFGEN) .

.PHONY: push-gadget-container
push-gadget-container:
	docker push $(CONTAINER_REPO):$(IMAGE_TAG)

# kubectl-gadget container image
.PHONY: kubectl-gadget-container
kubectl-gadget-container:
	docker buildx build -t kubectl-gadget -f Dockerfiles/kubectl-gadget.Dockerfile \
	--build-arg IMAGE_TAG=$(IMAGE_TAG) .

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

.PHONY: gadgets-unit-tests
gadgets-unit-tests:
	go test -test.v -exec sudo ./pkg/gadgets/...

.PHONY: local-gadget-tests
local-gadget-tests:
	# Compile and execute in separate commands because Go might not be
	# available in the root environment
	go test -c ./pkg/local-gadget-manager \
		-tags withebpf
	sudo ./local-gadget-manager.test -test.v -root-test $$LOCAL_GADGET_TESTS_PARAMS
	rm -f ./local-gadget-manager.test

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-run TestExecsnoop -v -no-deploy-ig -no-deploy-spo" make integration-tests
.PHONY: integration-tests
integration-tests: kubectl-gadget
	KUBECTL_GADGET="$(shell pwd)/kubectl-gadget" \
		go test ./integration/... \
			-integration \
			-timeout 20m \
			-k8s-distro $(KUBERNETES_DISTRIBUTION) \
			-image $(CONTAINER_REPO):$(IMAGE_TAG) \
			$$INTEGRATION_TESTS_PARAMS

.PHONY: generate-documentation
generate-documentation:
	go run -tags docs cmd/gen-doc/gen-doc.go -repo $(shell pwd)

lint:
# This version number must be kept in sync with CI workflow lint one.
# XDG_CACHE_HOME is necessary to avoid this type of errors:
# ERRO Running error: context loading failed: failed to load packages: failed to load with go/packages: err: exit status 1: stderr: failed to initialize build cache at /.cache/go-build: mkdir /.cache: permission denied
# Process 15167 has exited with status 3
# While GOLANGCI_LINT_CACHE is used to store golangci-lint cache.
	docker run --rm --env XDG_CACHE_HOME=/tmp/xdg_home_cache \
		--env GOLANGCI_LINT_CACHE=/tmp/golangci_lint_cache \
		--user $(shell id -u):$(shell id -g) -v $(shell pwd):/app -w /app \
		golangci/golangci-lint:v1.49.0 golangci-lint run --fix

# minikube
LIVENESS_PROBE ?= true
.PHONY: minikube-install
minikube-install: gadget-default-container kubectl-gadget
	@echo "Image on the host:"
	docker image list --format "table {{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}" |grep $(CONTAINER_REPO):$(IMAGE_TAG)
	@echo
	# Unfortunately, minikube-cache and minikube-image have bugs in older
	# versions. And new versions of minikube don't support all eBPF
	# features. So we have to keep "docker-save|docker-load" when
	# available.
	if $(MINIKUBE) docker-env >/dev/null 2>&1 ; then \
		docker save $(CONTAINER_REPO):$(IMAGE_TAG) $(PV) | (eval $$($(MINIKUBE) -p minikube docker-env | grep =) && docker load) ; \
	else \
		$(MINIKUBE) image load $(CONTAINER_REPO):$(IMAGE_TAG) ; \
	fi
	@echo "Image in Minikube:"
	$(MINIKUBE) image ls --format=table | grep "$(CONTAINER_REPO)\s*|\s*$(IMAGE_TAG)" || true
	@echo
	# Remove all resources created by Inspektor Gadget.
	./kubectl-gadget undeploy || true
	./kubectl-gadget deploy --liveness-probe=$(LIVENESS_PROBE) \
		--image-pull-policy=Never
	kubectl rollout status daemonset -n gadget gadget --timeout 30s
	@echo "Image used by the gadget pod:"
	kubectl get pod -n gadget -o yaml|grep imageID:

.PHONY: btfgen
btfgen:
	+make -f Makefile.btfgen
