SHELL := /bin/bash

ROOT_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/ebpf-builder:latest
IG ?= ig
KUBECTL_GADGET ?= kubectl-gadget
IG_RUNTIME ?= docker
IG_FLAGS ?=
COSIGN ?= cosign

GADGETS = \
	audit_seccomp \
	profile_blockio \
	trace_bind \
	trace_capabilities \
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
	top_tcp \
	snapshot_process \
	snapshot_socket \
	ci/sched_cls_drop \
	#

DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

GADGETS_README = $(addsuffix /README.mdx, $(GADGETS))

.PHONY: all
all: build

build: $(GADGETS)

readmes: $(GADGETS_README)
	counter=10 ; for i in $(shell git grep '^sidebar_position:' -- .|cut -d: -f1|grep /README.mdx) ; do sed -i "s/^sidebar_position:.*/sidebar_position: $$counter/g" $$i ; counter=$$(($$counter + 10)) ; done

# GADGET_BUILD_PARAMS can be used to pass additional parameters e.g
# GADGET_BUILD_PARAMS="--update-metadata" make build
.PHONY: $(GADGETS)
$(GADGETS):
	@echo "Building $@"
	@sudo -E \
		IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/..) \
		$(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		-t $(GADGET_REPOSITORY)/$@:$(GADGET_TAG) \
		$$GADGET_BUILD_PARAMS \
		$@

.PHONY: $(GADGETS_README)
$(GADGETS_README):
	@# Create README if not exists
	if [ ! -f "$@" ] ; then \
		gomplate -d gadget=$(@:README.mdx=gadget.yaml) -d artifacthubpkg=$(@:README.mdx=artifacthub-pkg.yml) --file README.template --out $@ ; \
	fi
	@# Replace flags section
	sed -i '/^## Flags/,/^## /{/^## /!d}' $@
	sed -i '/## Flags/r '<(gomplate -d gadget=$(@:README.mdx=gadget.yaml) -d artifacthubpkg=$(@:README.mdx=artifacthub-pkg.yml) --file README-flags.template) $@

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		sudo -E $(IG) image push $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG) || exit 1 ; \
	done

sign: push
	@echo "Signing all gadgets"
	for GADGET in $(GADGETS); do \
		digest=$$(sudo -E $(IG) image list --no-trunc | grep "$$GADGET " | awk '{ print $$3 }') ; \
		cosign sign --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$$GADGET@$$digest || exit 1 ; \
	done

.PHONY:
clean:
	for GADGET in $(GADGETS); do \
		sudo -E $(IG) image remove $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done

.PHONY:
test: build
	IG_PATH=$(IG_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	go test -exec 'sudo -E' -v ./...

.PHONY:
test-local: IG_PATH=$(IG)
test-local: test

.PHONY:
test-k8s: IG_PATH=$(KUBECTL_GADGET)
test-k8s: test
