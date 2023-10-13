TAG := `git describe --tags --always`
VERSION :=

CONTAINER_REPO ?= ghcr.io/inspektor-gadget/inspektor-gadget
IMAGE_TAG ?= $(shell ./tools/image-tag branch)

MINIKUBE ?= minikube
KUBERNETES_DISTRIBUTION ?= ""
GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget

GOHOSTOS ?= $(shell go env GOHOSTOS)
GOHOSTARCH ?= $(shell go env GOHOSTARCH)

KUBERNETES_ARCHITECTURE ?= $(GOHOSTARCH)

ENABLE_BTFGEN ?= false

BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# This version number must be kept in sync with CI workflow lint one.
LINTER_VERSION ?= v1.49.0

EBPF_BUILDER ?= ghcr.io/inspektor-gadget/ebpf-builder:latest

DNSTESTER_IMAGE ?= "ghcr.io/inspektor-gadget/dnstester:latest"

PLATFORMS ?= "linux/amd64,linux/arm64"

CLANG_FORMAT ?= clang-format

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
include minikube.mk

LDFLAGS := "-X github.com/inspektor-gadget/inspektor-gadget/cmd/common.version=$(VERSION) \
-X main.gadgetimage=$(CONTAINER_REPO):$(IMAGE_TAG) \
-extldflags '-static'"

.DEFAULT_GOAL := build
.PHONY: build
build: manifests generate kubectl-gadget gadget-container

.PHONY: all
all: build ig

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

ebpf-objects:
	docker run --rm --name ebpf-object-builder --user $(shell id -u):$(shell id -g) \
		-v $(shell pwd):/work $(EBPF_BUILDER) \
		make ebpf-objects-outside-docker

ebpf-objects-outside-docker:
# We need <asm/types.h> and depending on Linux distributions, it is installed
# at different paths:
#
# * Ubuntu, package linux-libc-dev:
#   /usr/include/x86_64-linux-gnu/asm/types.h
#
# * Fedora, package kernel-headers
#   /usr/include/asm/types.h
#
# Since Ubuntu does not install it in a standard path, add a compiler flag for
# it.
	TARGET=arm64 CFLAGS="-I/usr/include/$(uname -m)-linux-gnu -I$(shell pwd)/include/gadget/arm64/ -I$(shell pwd)/include/" go generate ./...
	TARGET=amd64 CFLAGS="-I/usr/include/$(uname -m)-linux-gnu -I$(shell pwd)/include/gadget/amd64/ -I$(shell pwd)/include/" go generate ./...

# ig

IG_TARGETS = \
	ig-linux-amd64 \
	ig-linux-arm64

.PHONY: list-ig-targets
list-ig-targets:
	@echo $(IG_TARGETS)

.PHONY: ig-all
ig-all: $(IG_TARGETS) ig

ig: ig-$(GOHOSTOS)-$(GOHOSTARCH)
	cp ig-$(GOHOSTOS)-$(GOHOSTARCH) ig

.PHONY: install/ig
install/ig: ig
	sudo cp ig /usr/local/bin/ig

ig-%: phony_explicit
	echo Building $@
	if $(ENABLE_BTFGEN) == "true" ; then \
		./tools/getbtfhub.sh && \
		$(MAKE) -f Makefile.btfgen \
			ARCH=$(subst linux-,,$*) BTFHUB_ARCHIVE=$(HOME)/btfhub-archive/ -j$(nproc); \
	fi
	docker buildx build --load --platform=$(subst -,/,$*) -t $@ -f Dockerfiles/ig.Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg EBPF_BUILDER=$(EBPF_BUILDER) .
	docker create --name ig-$*-container $@
	docker cp ig-$*-container:/usr/bin/ig $@
	docker rm ig-$*-container
	chmod +x $@

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
	cp kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH)$(if $(findstring windows,$*),.exe,) kubectl-gadget$(if $(findstring windows,$*),.exe,)

kubectl-gadget-%: phony_explicit
	export GO111MODULE=on CGO_ENABLED=0 && \
	export GOOS=$(shell echo $* | cut -f1 -d-) GOARCH=$(shell echo $* | cut -f2 -d-) && \
	go build -ldflags $(LDFLAGS) \
		-tags withoutebpf \
		-o kubectl-gadget-$${GOOS}-$${GOARCH}$(if $(findstring windows,$*),.exe,) \
		github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget

.PHONY: install/kubectl-gadget
install/kubectl-gadget: kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH)
	mkdir -p ~/.local/bin/
	cp kubectl-gadget-$(GOHOSTOS)-$(GOHOSTARCH) ~/.local/bin/kubectl-gadget

GADGETCTL_TARGETS = \
	gadgetctl-linux-amd64 \
	gadgetctl-linux-arm64 \
	gadgetctl-darwin-amd64 \
	gadgetctl-darwin-arm64 \
	gadgetctl-windows-amd64

.PHONY: list-gadgetctl-targets
list-gadgetctl-targets:
	@echo $(GADGETCTL_TARGETS)

.PHONY: gadgetctl-all
gadgetctl-all: $(GADGETCTL_TARGETS) gadgetctl

gadgetctl: gadgetctl-$(GOHOSTOS)-$(GOHOSTARCH)
	cp gadgetctl-$(GOHOSTOS)-$(GOHOSTARCH)$(if $(findstring windows,$*),.exe,) gadgetctl$(if $(findstring windows,$*),.exe,)

gadgetctl-%: phony_explicit
	export GO111MODULE=on CGO_ENABLED=0 && \
	export GOOS=$(shell echo $* |cut -f1 -d-) GOARCH=$(shell echo $* |cut -f2 -d-) && \
	go build -ldflags $(LDFLAGS) \
		-tags withoutebpf \
		-o gadgetctl-$${GOOS}-$${GOARCH}$(if $(findstring windows,$*),.exe,) \
		github.com/inspektor-gadget/inspektor-gadget/cmd/gadgetctl

.PHONY: install/gadgetctl
install/gadgetctl: gadgetctl-$(GOHOSTOS)-$(GOHOSTARCH)
	mkdir -p ~/.local/bin/
	cp gadgetctl-$(GOHOSTOS)-$(GOHOSTARCH) ~/.local/bin/gadgetctl

.PHONY: gadget-container
gadget-container:
	if $(ENABLE_BTFGEN) == "true" ; then \
		./tools/getbtfhub.sh && \
		$(MAKE) -f Makefile.btfgen \
			BTFHUB_ARCHIVE=$(HOME)/btfhub-archive/ -j$(nproc); \
	fi
	docker buildx build --load -t $(CONTAINER_REPO):$(IMAGE_TAG) \
		-f Dockerfiles/gadget.Dockerfile .

.PHONY: cross-gadget-container
cross-gadget-container:
	if $(ENABLE_BTFGEN) == "true" ; then \
		./tools/getbtfhub.sh && \
		$(MAKE) -f Makefile.btfgen \
			ARCH=x86 BTFHUB_ARCHIVE=$(HOME)/btfhub-archive/ -j$(nproc) && \
		$(MAKE) -f Makefile.btfgen \
			ARCH=arm64 BTFHUB_ARCHIVE=$(HOME)/btfhub-archive/ -j$(nproc); \
	fi
	docker buildx build --platform=$(PLATFORMS) -t $(CONTAINER_REPO):$(IMAGE_TAG) \
		--push \
		-f Dockerfiles/gadget.Dockerfile .

push-gadget-container:
	docker push $(CONTAINER_REPO):$(IMAGE_TAG)

# kubectl-gadget container image
.PHONY: kubectl-gadget-container
kubectl-gadget-container:
	docker buildx build --load -t kubectl-gadget -f Dockerfiles/kubectl-gadget.Dockerfile \
	--build-arg IMAGE_TAG=$(IMAGE_TAG) .

.PHONY: cross-kubectl-gadget-container
cross-kubectl-gadget-container:
	docker buildx build --platform=$(PLATFORMS) -t kubectl-gadget -f Dockerfiles/kubectl-gadget.Dockerfile \
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
	go test -test.v -exec sudo ./...

# Individual tests can be selected with a command such as:
# go test -exec sudo -ldflags="-s=false" -bench='^BenchmarkAllGadgetsWithContainers$/^container100$/snapshot-socket' -run=Benchmark ./internal/benchmarks/... -count 10
.PHONY: gadgets-benchmarks
gadgets-benchmarks:
	go test -exec sudo -ldflags="-s=false" -bench=. -run=Benchmark ./pkg/gadgets/... ./internal/benchmarks/...

.PHONY: ig-tests
ig-tests:
	# Compile and execute in separate commands because Go might not be
	# available in the root environment
	go test -c ./pkg/ig-manager
	sudo ./ig-manager.test -test.v $$IG_TESTS_PARAMS
	rm -f ./ig-manager.test

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-run TestTraceExec -no-deploy-ig -no-deploy-spo" make integration-tests
.PHONY: integration-tests
integration-tests: kubectl-gadget
	KUBECTL_GADGET="$(shell pwd)/kubectl-gadget" \
		go test ./integration/inspektor-gadget/... \
			-v \
			-integration \
			-timeout 30m \
			-k8s-distro $(KUBERNETES_DISTRIBUTION) \
			-k8s-arch $(KUBERNETES_ARCHITECTURE) \
			-image $(CONTAINER_REPO):$(IMAGE_TAG) \
			-dnstester-image $(DNSTESTER_IMAGE) \
			-gadget-repository $(GADGET_REPOSITORY) \
			-gadget-tag $(GADGET_TAG) \
			$$INTEGRATION_TESTS_PARAMS

.PHONY: generate-documentation
generate-documentation:
	go run -tags docs cmd/gen-doc/gen-doc.go -repo $(shell pwd)

lint:
	docker build -t linter -f Dockerfiles/linter.Dockerfile --build-arg VERSION=$(LINTER_VERSION) Dockerfiles
# XDG_CACHE_HOME is necessary to avoid this type of errors:
# ERRO Running error: context loading failed: failed to load packages: failed to load with go/packages: err: exit status 1: stderr: failed to initialize build cache at /.cache/go-build: mkdir /.cache: permission denied
# Process 15167 has exited with status 3
# While GOLANGCI_LINT_CACHE is used to store golangci-lint cache.
	docker run --rm --env XDG_CACHE_HOME=/tmp/xdg_home_cache \
		--env GOLANGCI_LINT_CACHE=/tmp/golangci_lint_cache \
		--user $(shell id -u):$(shell id -g) -v $(shell pwd):/app -w /app \
		linter

clang-format:
	find ./ -type f \( -iname '*.h' ! -iname "vmlinux.h" \) -o -iname '*.c' -execdir $(CLANG_FORMAT) -i {} \;

# minikube
LIVENESS_PROBE ?= true
.PHONY: minikube-deploy
minikube-deploy: minikube-start gadget-container kubectl-gadget
	@echo "Image on the host:"
	docker image list --format "table {{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}" |grep $(CONTAINER_REPO):$(IMAGE_TAG)
	@echo
	# Unfortunately, minikube-cache and minikube-image have bugs in older
	# versions. And new versions of minikube don't support all eBPF
	# features. So we have to keep "docker-save|docker-load" when
	# available.
	if $(MINIKUBE) docker-env >/dev/null 2>&1 ; then \
		docker save $(CONTAINER_REPO):$(IMAGE_TAG) $(PV) | (eval $$($(MINIKUBE) docker-env | grep =) && docker load) ; \
	else \
		$(MINIKUBE) image load $(CONTAINER_REPO):$(IMAGE_TAG) ; \
	fi
	@echo "Image in Minikube:"
	$(MINIKUBE) image ls --format=table | grep "$(CONTAINER_REPO)\s*|\s*$(IMAGE_TAG)" || \
		(echo "Image $(CONTAINER_REPO)\s*|\s*$(IMAGE_TAG) was not correctly loaded into Minikube" && false)
	@echo
	# Remove all resources created by Inspektor Gadget.
	./kubectl-gadget undeploy || true
	./kubectl-gadget deploy --liveness-probe=$(LIVENESS_PROBE) \
		--image-pull-policy=Never
	kubectl rollout status daemonset -n gadget gadget --timeout 30s
	@echo "Image used by the gadget pod:"
	kubectl get pod -n gadget -o yaml|grep imageID:
	@echo "Minikube profile used:"
	$(MINIKUBE) profile

.PHONY: btfgen
btfgen:
	+make -f Makefile.btfgen

.PHONY: generate-manifests
generate-manifests:
	echo "---" > pkg/resources/manifests/deploy.yaml
	echo "# This file is generated by 'make generate-manifests'; DO NOT EDIT." >> pkg/resources/manifests/deploy.yaml
	cat pkg/resources/manifests/namespace.yaml >> pkg/resources/manifests/deploy.yaml
	make -C charts APP_VERSION=latest template
	cat charts/bin/deploy.yaml >> pkg/resources/manifests/deploy.yaml

.PHONY: install-headers
install-headers:
	cp -r ./include/gadget/ /usr/include/

.PHONY: remove-headers
remove-headers:
	rm -rf /usr/include/gadget

.PHOHY: build-gadgets
build-gadgets: install/ig
	$(MAKE) -C gadgets/ build

.PHOHY: push-gadgets
push-gadgets: install/ig
	$(MAKE) -C gadgets/ push

.PHONY: help
help:
	@echo  'Building targets:'
	@echo  '  all		  		- Build all targets marked with [*]'
	@echo  '* ig		  		- Build the ig cli tool'
	@echo  '  ig-all	  		- Build the ig cli tool for all architectures'
	@echo  '* build		  		- Build all targets marked with [o]'
	@echo  'o manifests			- Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects'
	@echo  'o generate			- Generate client API code and DeepCopy related code'
	@echo  'o kubectl-gadget		- Build the kubectl plugin'
	@echo  '  kubectl-gadget-all		- Build the kubectl plugin for all architectures'
	@echo  '  kubectl-gadget-container	- Build container for kubectl-gadget'
	@echo  'o gadget-container		- Build the gadget container image for the host architecture'
	@echo  '  cross-gadget-container	- Build the gadget container image for all supported architectures'
	@echo  '  ebpf-objects			- Build eBPF objects file inside docker'
	@echo  '  ebpf-objects-outside-docker	- Build eBPF objects file on host'
	@echo  '  btfgen			- Build BTF files'
	@echo  '  list-ig-targets		- List ig available architectures'
	@echo  '  list-kubectl-gadget-targets	- List kubectl plugin available architectures'
	@echo  '  build-gadgets			- Build all gadgets'
	@echo  '  push-gadgets			- Push all gadgets'
	@echo  ''
	@echo  'Testing targets:'
	@echo  '  test				- Run unit tests'
	@echo  '  controller-tests		- Run controllers unit tests'
	@echo  '  ig-tests			- Run ig manager unit tests'
	@echo  '  gadgets-unit-tests		- Run gadget unit tests'
	@echo  '  integration-tests		- Run integration tests'
	@echo  ''
	@echo  'Installing targets:'
	@echo  '  install/kubectl-gadget	- Build kubectl plugin and install it in ~/.local/bin'
	@echo  '  install/ig	  		- Build and install ig cli tool in /usr/local/bin'
	@echo  ''
	@echo  'Development targets:'
	@echo  '  clang-format			- Format ebpf source files'
	@echo  '  lint				- Lint the Go code'
	@echo  '  generate-documentation	- Generate documentation for gadgets and trace CRD'
	@echo  '  generate-manifests		- Generate manifests for the gadget deployment'
	@echo  '  minikube-start		- Start a kubernetes cluster using minikube with the docker driver'
	@echo  '  minikube-deploy		- Build and deploy the gadget container on minikube with docker driver, the cluster is started if it does not exist'
	@echo  '  install-headers		- Install headers used to build gadgets in /usr/include/gadget'
	@echo  '  remove-headers		- Remove headers installed in /usr/include/gadget'
