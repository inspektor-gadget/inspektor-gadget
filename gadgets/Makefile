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
COSIGN_FLAGS ?=
CRANE ?= crane
VIMTO ?= vimto
VIMTO_VM_MEMORY ?= 4096M
DOCKER ?= docker
# sudo resets the environment, so anything the command needs has to be passed
# on the sudo command line or named in --preserve-env. `sudo -E` is not usable
# here: sudo-rs, the default sudo implementation since Ubuntu 25.10, does not
# implement it. It prints a warning and runs the command with a reset
# environment, which makes the gadget tests skip themselves rather than fail.
SUDO ?= sudo
#
# The variables that used to be carried over by `sudo -E`, enumerated:
#
# - HOME, because a lot of things are derived from it. The commands talking to
#   a registry (push, pull, inspect) fall back to the docker credentials of
#   ~/.docker/config.json, which is how the CI authenticates: it logs in with
#   docker/login-action, which writes the config file of the runner user.
#   DOCKER_CONFIG overrides that path, so it is needed as well.
# - The DOCKER_* variables, because `ig image build` runs the builder in a
#   container through a docker client configured from the environment.
# - XDG_CACHE_HOME and HOME, because vimto caches the kernel images it pulls in
#   $XDG_CACHE_HOME/vimto, falling back to ~/.cache.
# - The GO* variables, because the unit tests run go under sudo inside vimto.
# - The IG_*, GADGET_* and TEST_* variables that the gadget tests read from
#   their environment. They are exported by the test recipes below, and vimto
#   passes its own environment to the command it runs in the VM.
# - KERNEL_VERSION, which the workflow sets and some tests read to skip
#   themselves on the ci-kernels images, e.g. trace_fsslower, whose filesystem
#   is not present there. Dropping it makes those tests run and fail rather
#   than skip.
#
# sudo silently ignores the variables of the list that are not set, so a single
# list can serve every command. Keeping one list rather than a tailored one per
# command is deliberate: `-E` passed everything, so anything left out here is a
# silent behaviour change rather than an error.
#
# --preserve-env takes a comma separated list, which keeps this a single
# whitespace free token. That matters for `go test -exec`, which splits its
# argument on whitespace with no quote handling: an `env VAR=value` prefix
# could not carry a value containing spaces, such as an IG_FLAGS with more than
# one flag.
#
# The list is written one variable per line for readability and joined
# afterwards: a backslash continuation expands to a space, so the names are
# collected whitespace separated and the spaces are then turned into commas.
# "$() " below is a literal space; the comma needs a variable because a literal
# one would be taken as an argument separator by $(subst ...).
SUDO_ENV_COMMA := ,
SUDO_ENV_VARS = \
	HOME \
	DOCKER_CONFIG \
	DOCKER_HOST \
	DOCKER_TLS_VERIFY \
	DOCKER_CERT_PATH \
	DOCKER_API_VERSION \
	XDG_CACHE_HOME \
	GOFLAGS \
	GOPATH \
	GOCACHE \
	GOMODCACHE \
	IG_PATH \
	IG_RUNTIME \
	IG_FLAGS \
	IG_SOURCE_PATH \
	IG_EXPERIMENTAL \
	IG_VERIFY_IMAGE \
	IG_DEBUG_LOGS \
	GPU_EBPF_BRIDGE_PATH \
	GADGET_REPOSITORY \
	GADGET_TAG \
	TEST_DNS_SERVER_IMAGE \
	TEST_DNS_CLIENT_IMAGE \
	KUBERNETES_DISTRIBUTION \
	KERNEL_VERSION
SUDO_ENV = $(subst $() ,$(SUDO_ENV_COMMA),$(strip $(SUDO_ENV_VARS)))
# Empty when SUDO is overridden to nothing, e.g. when running as root, so that
# the option string is not mistaken for the command to run.
SUDO_E ?= $(if $(SUDO),$(SUDO) --preserve-env=$(SUDO_ENV))

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

.PHONY: list-gadgets
list-gadgets:
	@printf '%s\n' $(GADGETS)

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
	@$(SUDO_E) \
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
	@$(SUDO_E) \
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
	@$(SUDO_E) $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY: push
push: $(addsuffix -push,$(GADGETS))

%-push-existing: % phony_explicit
	@echo "Pushing existing $*"
	@n=0; \
	until $(SUDO_E) $(IG) image push $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) $(IG_FLAGS); do \
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
	digest=$$($(SUDO_E) $(IG) image inspect $(GADGET_REPOSITORY)/$*:$(GADGET_TAG) -o json | jq -r .Digest) ; \
	$(COSIGN) sign $(COSIGN_FLAGS) --key env://COSIGN_PRIVATE_KEY --yes --recursive $(GADGET_REPOSITORY)/$*@$$digest

.PHONY: sign
sign: $(addsuffix -sign,$(GADGETS))

%-sign-existing: phony_explicit
	@echo "Signing existing $*"
	@digest=$$($(SUDO_E) $(IG) image list --no-trunc | grep "$* " | awk '{ print $$3 }') ; \
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
	$(SUDO_E) $(IG) image remove $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

.PHONY: clean
clean: $(addsuffix -clean,$(GADGETS))

.PHONY: pull
pull:
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) && \
	for GADGET in $(GADGETS); do \
		$(SUDO_E) $(IG) image pull $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done

%/pull: phony_explicit
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	$(SUDO_E) $(IG) image pull $(GADGET_REPOSITORY)/$*:$(GADGET_TAG)

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
		$(SUDO_E) PATH="$$PATH" $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./.../$(UNIT_TEST_DIR)/..., \
		go test -v -exec '$(SUDO_E)' ./.../$(UNIT_TEST_DIR)/...)

%/test-unit: % phony_explicit
	# use PATH preservation to find **right** go binary inside vimto as it's run as sudo
	IG_VERIFY_IMAGE=$(IG_VERIFY_IMAGE) \
	IG_DEBUG_LOGS=$(IG_DEBUG_LOGS) \
	GADGET_TAG=$(GADGET_TAG) \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	VIMTO=$(VIMTO) \
	VIMTO_VM_MEMORY=$(VIMTO_VM_MEMORY) \
	$(if $(KERNEL_VERSION), \
		$(SUDO_E) PATH="$$PATH" $(VIMTO) -kernel $(KERNEL_REPOSITORY):$(KERNEL_VERSION) \
		-memory $(VIMTO_VM_MEMORY) -- go test -v ./$*/$(UNIT_TEST_DIR)/..., \
		go test -v -exec '$(SUDO_E)' ./$*/$(UNIT_TEST_DIR)/...)

%/test-integration: % phony_explicit
	IG_PATH=$(IG_PATH) \
	IG_RUNTIME=$(IG_RUNTIME) \
	GPU_EBPF_BRIDGE_PATH=$(GPU_EBPF_BRIDGE_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	TEST_DNS_SERVER_IMAGE=$(DNSTESTER_IMAGE) \
	go test -v -exec '$(SUDO_E)' ./$*/$(INTEGRATION_TEST_DIR)/...

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
	IG_RUNTIME=$(IG_RUNTIME) \
	GPU_EBPF_BRIDGE_PATH=$(GPU_EBPF_BRIDGE_PATH) \
	CGO_ENABLED=0 \
	GADGET_REPOSITORY=$(GADGET_REPOSITORY) \
	GADGET_TAG=$(GADGET_TAG) \
	IG_FLAGS=$(IG_FLAGS) \
	TEST_DNS_SERVER_IMAGE=$(DNSTESTER_IMAGE) \
	go test -v -exec '$(SUDO_E)' ./.../$(INTEGRATION_TEST_DIR)/...

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
