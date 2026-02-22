SHELL := /bin/bash

ROOT_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/gadget-builder:main
KERNEL_REPOSITORY ?= ghcr.io/inspektor-gadget/ci-kernels
IG ?= ig
KUBECTL_GADGET ?= kubectl-gadget
IG_RUNTIME ?= docker
IG_FLAGS ?=
IG_DEBUG_LOGS ?= true
COSIGN ?= cosign
COSIGN_FLAGS ?=
CRANE ?= crane
VIMTO ?= vimto
VIMTO_VM_MEMORY ?= 4096M
DOCKER ?= docker

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
	profile_qdisc_latency \
	profile_tcprtt \
	tcpdump \
	trace_bind \
	trace_capabilities \
	trace_dns \
	trace_exec \
	trace_fsslower \
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
	snapshot_file \
	#

DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

GADGETS_README = $(filter-out ci/%, $(addsuffix /README.mdx, $(GADGETS)))
GADGETS_README_DEV = $(filter-out ci/%, $(addsuffix /dev.md, $(GADGETS)))

.PHONY: all
all: build

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
	@sudo -E \
		IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/..) \
		$(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		-t $(GADGET_REPOSITORY)/$@:$(GADGET_TAG) \
		--builder-image-pull=never \
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

%-push: %-build
	@echo "Pushing $*"
	@sudo -E $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY:
push: $(addsuffix -push,$(GADGETS))

%-push-existing: %
	@echo "Pushing existing $*"
	@sudo -E $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) $(IG_FLAGS)

.PHONY:
push-existing: $(addsuffix -push-existing,$(GADGETS))

%-sign: %-push
	@echo "Signing $*"
	digest=$$(sudo -E $(IG) image inspect $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) -o json | jq -r .Digest) ; \
	$(COSIGN) sign $(COSIGN_FLAGS) --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest

sign: $(addsuffix -sign,$(GADGETS))

%-sign-existing:
	@echo "Signing existing $*"
	digest=$$(sudo -E $(IG) image list --no-trunc | grep "$* " | awk '{ print $$3 }') ; \
	$(COSIGN) sign $(COSIGN_FLAGS) --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest

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
	# use PATH preservation to find **right** go binary inside vimto as it's run as sudo
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		sudo -E PATH="$$PATH" $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./.../$(UNIT_TEST_DIR)/..., \
		go test -v -exec 'sudo -E' ./.../$(UNIT_TEST_DIR)/...)

.PHONY:
%/test-unit: %
	# use PATH preservation to find **right** go binary inside vimto as it's run as sudo
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		sudo -E PATH="$$PATH" $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
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

.PHONY:
%-update-latest-tag:
	$(CRANE) copy $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) $(GADGET_REPOSITORY)/$*:latest

.PHONY:
update-latest-tag: $(addsuffix -update-latest-tag,$(GADGETS))
