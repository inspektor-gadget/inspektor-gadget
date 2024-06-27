SHELL := /bin/bash

ROOT_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/ebpf-builder:latest
IG ?= ig
KUBECTL_GADGET ?= kubectl-gadget
IG_FLAGS ?=
COSIGN ?= cosign
GADGETS = \
	trace_dns \
	trace_exec \
	trace_lsm \
	trace_malloc \
	trace_mount \
	trace_oomkill \
	trace_open \
	trace_signal \
	trace_sni \
	trace_ssl \
	trace_tcp \
	trace_tcpconnect \
	trace_tcpdrop \
	trace_tcpretrans \
	top_file \
	snapshot_process \
	snapshot_socket \
	ci/sched_cls_drop \
	#

GADGETS_README = $(addsuffix /README.md, $(GADGETS))

.PHONY: all
all: build

build: $(GADGETS)

readmes: $(GADGETS_README)

# GADGET_BUILD_PARAMS can be used to pass additional parameters e.g
# GADGET_BUILD_PARAMS="--update-metadata" make build
.PHONY: $(GADGETS)
$(GADGETS):
	@echo "Building $@"
	@sudo -E IG_EXPERIMENTAL=true \
		IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/..) \
		$(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		-t $(GADGET_REPOSITORY)/$@:$(GADGET_TAG) \
		$$GADGET_BUILD_PARAMS \
		$@

.PHONY: $(GADGETS_README)
$(GADGETS_README):
	gomplate -d gadget=$(@:README.md=gadget.yaml) < README.template > $@

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		sudo -E IG_EXPERIMENTAL=true $(IG) image push $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG) || exit 1 ; \
	done

sign: push
	@echo "Signing all gadgets"
	for GADGET in $(GADGETS); do \
		digest=$$(sudo -E IG_EXPERIMENTAL=true $(IG) image list --no-trunc | grep "$$GADGET " | awk '{ print $$3 }') ; \
		cosign sign --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$$GADGET@$$digest || exit 1 ; \
	done

.PHONY:
clean:
	for GADGET in $(GADGETS); do \
		sudo -E IG_EXPERIMENTAL=true $(IG) image remove $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done

.PHONY:
test-ig-local: build
	IG_PATH=$(IG) \
	IG_RUNTIME=docker \
	CGO_ENABLED=0 \
	IG_EXPERIMENTAL=true \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	find . -name '*_test.go' -execdir go test -exec 'sudo -E' -v ./... \;

.PHONY:
test-k8s: build
	IG_PATH=$(KUBECTL_GADGET) \
	IG_RUNTIME=kubernetes \
	CGO_ENABLED=0 \
	IG_EXPERIMENTAL=true \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	find . -name '*_test.go' -execdir go test -exec 'sudo -E' -v ./... \;
