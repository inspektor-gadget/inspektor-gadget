SHELL := /bin/bash

ROOT_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/ebpf-builder:main
KERNEL_REPOSITORY ?= ghcr.io/inspektor-gadget/ci-kernels
IG ?= ig
KUBECTL_GADGET ?= kubectl-gadget
IG_RUNTIME ?= docker
IG_FLAGS ?=
IG_DEBUG_LOGS ?= true
COSIGN ?= cosign
VIMTO ?= vimto
VIMTO_VM_MEMORY ?= 4096M

UNIT_TEST_DIR = test/unit
INTEGRATION_TEST_DIR = test/integration

GADGETS = \
	advise_seccomp \
	audit_seccomp \
	deadlock \
	fdpass \
	fsnotify \
	profile_blockio \
	profile_qdisc_latency \
	profile_tcprtt \
	trace_bind \
	trace_capabilities \
	trace_dns \
	trace_exec \
	trace_fsslower \
	trace_lsm \
	trace_malloc \
	trace_mount \
	trace_oomkill \
	trace_open \
	trace_signal \
	trace_sni \
	trace_ssl \
	trace_tcp \
	trace_tcpdrop \
	trace_tcpretrans \
	top_blockio \
	top_file \
	top_tcp \
	snapshot_process \
	snapshot_socket \
	ci/datasource-containers \
	ci/inner_fields \
	ci/sched_cls_drop \
	#

DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

GADGETS_README = $(filter-out ci/%, $(addsuffix /README.mdx, $(GADGETS)))

.PHONY: all
all: build

build: $(GADGETS)

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
	@# Create symlinks for README if not exists
	if [ ! -f $(ROOT_DIR)../docs/gadgets/$(@) ] ; then \
		ln -sf ../../gadgets/$@ $(ROOT_DIR)../docs/gadgets/$(shell dirname $@).mdx ; \
	fi

%-push: %-build
	@echo "Pushing $*"
	@sudo -E $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY:
push: $(addsuffix -push,$(GADGETS))

%-push-existing: %
	@echo "Pushing existing $*"
	@sudo -E $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY:
push-existing: $(addsuffix -push-existing,$(GADGETS))

%-sign: %-push
	@echo "Signing $*"
	digest=$$(sudo -E $(IG) image inspect $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) -o json | jq -r .Digest) ; \
	cosign sign --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest

sign: $(addsuffix -sign,$(GADGETS))

%-sign-existing:
	@echo "Signing existing $*"
	digest=$$(sudo -E $(IG) image list --no-trunc | grep "$* " | awk '{ print $$3 }') ; \
	cosign sign --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest

sign-existing: $(addsuffix -sign-existing,$(GADGETS))

%-clean:
	sudo -E $(IG) image remove $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY:
clean: $(addsuffix -clean,$(GADGETS))

.PHONY:
pull:
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) && \
	for GADGET in $(GADGETS); do \
		sudo -E $(IG) image pull $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done

.PHONY:
%/pull:
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	sudo -E $(IG) image pull $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY:
test-unit: build
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		sudo -E $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./.../$(UNIT_TEST_DIR)/..., \
		go test -v -exec 'sudo -E' ./.../$(UNIT_TEST_DIR)/...)

.PHONY:
%/test-unit: %
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		sudo -E $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./$*/$(UNIT_TEST_DIR)/..., \
		go test -v -exec 'sudo -E' ./$*/$(UNIT_TEST_DIR)/...)

.PHONY:
%/test-integration: %
	IG_PATH=$(IG_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	TEST_DNS_SERVER_IMAGE=$(DNSTESTER_IMAGE) \
	go test -v -exec 'sudo -E' ./$*/$(INTEGRATION_TEST_DIR)/...

.PHONY:
test-integration: build
	IG_PATH=$(IG_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	TEST_DNS_SERVER_IMAGE=$(DNSTESTER_IMAGE) \
	go test -v -exec 'sudo -E' ./.../$(INTEGRATION_TEST_DIR)/...

.PHONY:
test-local: IG_PATH=$(IG)
test-local: test-integration

.PHONY:
test-k8s: IG_PATH=$(KUBECTL_GADGET)
test-k8s: test-integration
