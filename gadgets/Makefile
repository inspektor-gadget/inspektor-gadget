SHELL := /bin/bash

ROOT_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/gadget-builder:main
KERNEL_REPOSITORY ?= ghcr.io/inspektor-gadget/ci-kernels
IG ?= ig
KUBECTL_GADGET ?= kubectl-gadget
# gpu-ebpf-bridge binary. Currently only used by gadgets/ci/gpu.
# The caller of test-local should either have gpu-ebpf-bridge on
# $PATH or override this variable to point at a pre-built binary.
GPU_EBPF_BRIDGE ?= gpu-ebpf-bridge
IG_RUNTIME ?= docker
IG_FLAGS ?=
# Number of times to retry pushing/signing a gadget after a failure.
# Defaults to 0 (a single attempt) so interactive users are not slowed
# down; CI sets this to work around flaky ghcr.io 500s on concurrent
# manifest PUTs.
GADGET_PUSH_RETRIES ?= 0
IG_DEBUG_LOGS ?= true
COSIGN ?= cosign
# Force using legacy .sig format.
# TODO Switch to bundle format.
COSIGN_FLAGS ?= --new-bundle-format=false --use-signing-config=false
CRANE ?= crane
VIMTO ?= vimto
VIMTO_VM_MEMORY ?= 4096M
DOCKER ?= docker
SUDO ?= sudo -E

UNIT_TEST_DIR = test/unit
INTEGRATION_TEST_DIR = test/integration

include minikube.mk

GADGETS ?= \
	advise_networkpolicy \
	advise_seccomp \
	audit_seccomp \
	bpfstats \
	deadlock \
	fdpass \
	fsnotify \
	profile_blockio \
	profile_cpu \
	profile_cuda \
	profile_qdisc_latency \
	profile_tcprtt \
	tcpdump \
	trace_bind \
	trace_capabilities \
	trace_dns \
	trace_exec \
	trace_fsslower \
	trace_link \
	trace_lsm \
	traceloop \
	trace_malloc \
	trace_mount \
	trace_oomkill \
	trace_init_module \
	trace_open \
	trace_signal \
	trace_sni \
	trace_ssl \
	trace_tcp \
	trace_tcpdrop \
	trace_tcpretrans \
	top_blockio \
	top_cpu_throttle \
	top_file \
	top_process \
	top_tcp \
	ttysnoop \
	snapshot_process \
	snapshot_socket \
	ci/datasource-containers \
	ci/inner_fields \
	ci/sched_cls_drop \
	ci/image_inspect \
	ci/container_filtering \
	ci/stacks \
	ci/uprobe \
	ci/gpu \
	ci/test_iter_map_elem \
	snapshot_file \
	top_cuda_memory \
	gpu_top \
	gpu_top_per_pid \
	trace_gpu_starvation \
	#

DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

GADGETS_README = $(filter-out ci/%, $(addsuffix /README.mdx, $(GADGETS)))
GADGETS_README_DEV = $(filter-out ci/%, $(addsuffix /dev.md, $(GADGETS)))

.PHONY: all
all: build

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

.PHONY: build
build: $(GADGETS)

# Pull the gadget builder in an independent step to avoid doing the same for
# each gadget, which introduces some overhead and increases the build time.
.PHONY: pull-builder-image
pull-builder-image:
	$(DOCKER) pull $(BUILDER_IMAGE)

# GADGET_BUILD_PARAMS can be used to pass additional parameters e.g
# GADGET_BUILD_PARAMS="--update-metadata" make build
.PHONY: $(GADGETS)
$(GADGETS): pull-builder-image
	@echo "Building $@"
	@$(SUDO) \
		IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/..) \
		$(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		-t $(GADGET_REPOSITORY)/$@:$(GADGET_TAG) \
		--builder-image-pull=never \
		$$GADGET_BUILD_PARAMS \
		$@

# Gadget sources embedded in the documentation (e.g. the hello-world guide).
# They are built to verify they compile, but never pushed.
DOCS_GADGETS = \
	../docs/gadget-devel/_hello-world-gadget/basic \
	../docs/gadget-devel/_hello-world-gadget/final \
	#

.PHONY: $(DOCS_GADGETS)
$(DOCS_GADGETS): pull-builder-image
	@echo "Building $@"
	@$(SUDO) \
		IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/..) \
		$(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		-t hello-world-docs-$(notdir $@):latest \
		--builder-image-pull=never \
		$@

.PHONY: validate-docs-gadgets
validate-docs-gadgets: $(DOCS_GADGETS)

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

# GADGET_README_DEV_PARAMS can be used to pass additional parameters e.g
# GADGET_README_DEV_PARAMS="--verify-image=false" make mygadget/dev.md
.PHONY: $(GADGETS_README_DEV)
$(GADGETS_README_DEV):
	@# Create dev.md if not exists
	@if [ ! -f "$@" ]; then \
		echo "Creating $@"; \
		touch $@; \
	fi
	@# Update dev.md with mermaid diagrams.
	echo -e "# Developer Notes\n\nThis file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget." > "$@"; \
	echo -e "\n## Program-Map interactions\n\nThe following diagrams are generated using the \`ig image inspect\` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime." >> "$@"
	echo -e "\n### Flowchart\n\n\`\`\`mermaid" >> "$@"
	sudo ig image inspect $(@:/dev.md=):$(GADGET_TAG) -o custom --extra-info=ebpf.flowchart $$GADGET_README_DEV_PARAMS >> "$@"
	echo "\`\`\`" >> "$@"
	echo -e "\n### Sequence Diagram\n\n\`\`\`mermaid" >> "$@"
	sudo ig image inspect $(@:/dev.md=):$(GADGET_TAG) -o custom --extra-info=ebpf.sequence $$GADGET_README_DEV_PARAMS >> "$@"
	echo -e "\`\`\`" >> "$@"

%-push: %-build phony_explicit
	@echo "Pushing $*"
	@$(SUDO) $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY: push
push: $(addsuffix -push,$(GADGETS))

%-push-existing: % phony_explicit
	@echo "Pushing existing $*"
	@n=0; \
	until $(SUDO) $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) $(IG_FLAGS); do \
		if [ $$n -ge $(GADGET_PUSH_RETRIES) ]; then \
			echo "Push of $* failed after $$n retries"; \
			exit 1; \
		fi; \
		n=$$((n+1)); \
		echo "Push of $* failed, retry $$n/$(GADGET_PUSH_RETRIES) in $$((n*5))s..."; \
		sleep $$((n*5)); \
	done

.PHONY: push-existing
push-existing: $(addsuffix -push-existing,$(GADGETS))

%-sign: %-push phony_explicit
	@echo "Signing $*"
	digest=$$($(SUDO) $(IG) image inspect $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) -o json | jq -r .Digest) ; \
	$(COSIGN) sign $(COSIGN_FLAGS) --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest

.PHONY: sign
sign: $(addsuffix -sign,$(GADGETS))

%-sign-existing: phony_explicit
	@echo "Signing existing $*"
	@digest=$$($(SUDO) $(IG) image list --no-trunc | grep "$* " | awk '{ print $$3 }') ; \
	n=0; \
	until $(COSIGN) sign $(COSIGN_FLAGS) --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest; do \
		if [ $$n -ge $(GADGET_PUSH_RETRIES) ]; then \
			echo "Signing of $* failed after $$n retries"; \
			exit 1; \
		fi; \
		n=$$((n+1)); \
		echo "Signing of $* failed, retry $$n/$(GADGET_PUSH_RETRIES) in $$((n*5))s..."; \
		sleep $$((n*5)); \
	done

.PHONY: sign-existing
sign-existing: $(addsuffix -sign-existing,$(GADGETS))

%-clean: phony_explicit
	$(SUDO) $(IG) image remove $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY: clean
clean: $(addsuffix -clean,$(GADGETS))

.PHONY: pull
pull:
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) && \
	for GADGET in $(GADGETS); do \
		$(SUDO) $(IG) image pull $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done

%/pull: phony_explicit
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	$(SUDO) $(IG) image pull $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY: test-unit
test-unit: build
	# use PATH preservation to find **right** go binary inside vimto as it's run as sudo
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		$(SUDO) PATH="$$PATH" $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./.../$(UNIT_TEST_DIR)/..., \
		go test -v -exec '$(SUDO)' ./.../$(UNIT_TEST_DIR)/...)

%/test-unit: % phony_explicit
	# use PATH preservation to find **right** go binary inside vimto as it's run as sudo
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		$(SUDO) PATH="$$PATH" $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./$*/$(UNIT_TEST_DIR)/..., \
		go test -v -exec '$(SUDO)' ./$*/$(UNIT_TEST_DIR)/...)

%/test-integration: % phony_explicit
	IG_PATH=$(IG_PATH) \
	GPU_EBPF_BRIDGE_PATH=$(GPU_EBPF_BRIDGE_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	TEST_DNS_SERVER_IMAGE=$(DNSTESTER_IMAGE) \
	go test -v -exec '$(SUDO)' ./$*/$(INTEGRATION_TEST_DIR)/...

# CI-only gadgets can ship a workload container image built locally from
# ci/<gadget>/workload/Dockerfile. It is tagged ig-<gadget>:test, e.g.
# ig-ci-uprobe:test, and is never pushed anywhere.
CI_WORKLOAD_GADGETS := $(patsubst %/workload/Dockerfile,%,$(wildcard ci/*/workload/Dockerfile))

.PHONY: $(addsuffix /workload-image,$(CI_WORKLOAD_GADGETS))
$(addsuffix /workload-image,$(CI_WORKLOAD_GADGETS)):
	$(eval CI_WORKLOAD_GADGET := $(patsubst %/workload-image,%,$@))
	$(DOCKER) build \
		-f $(CI_WORKLOAD_GADGET)/workload/Dockerfile \
		-t ig-$(subst /,-,$(CI_WORKLOAD_GADGET)):test \
		$(CI_WORKLOAD_GADGET)/workload

define CI_WORKLOAD_INTEGRATION_PREREQUISITE
$(1)/test-integration: $(1)/workload-image
endef
$(foreach gadget,$(CI_WORKLOAD_GADGETS),$(eval $(call CI_WORKLOAD_INTEGRATION_PREREQUISITE,$(gadget))))

.PHONY: test-integration
test-integration: build $(addsuffix /workload-image,$(filter $(GADGETS),$(CI_WORKLOAD_GADGETS)))
	IG_PATH=$(IG_PATH) \
	GPU_EBPF_BRIDGE_PATH=$(GPU_EBPF_BRIDGE_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	TEST_DNS_SERVER_IMAGE=$(DNSTESTER_IMAGE) \
	go test -v -exec '$(SUDO)' ./.../$(INTEGRATION_TEST_DIR)/...

.PHONY: test-local
test-local: IG_PATH=$(IG)
test-local: GPU_EBPF_BRIDGE_PATH=$(GPU_EBPF_BRIDGE)
test-local: test-integration

.PHONY: test-k8s
test-k8s: IG_PATH=$(KUBECTL_GADGET)
test-k8s: test-integration

%-update-latest-tag: phony_explicit
	$(CRANE) copy $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) $(GADGET_REPOSITORY)/$*:latest

.PHONY: update-latest-tag
update-latest-tag: $(addsuffix -update-latest-tag,$(GADGETS))
