SHELL := /bin/bash

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/ebpf-builder:latest
IG ?= ig
GADGETS = \
	trace_dns \
	trace_exec \
	trace_malloc \
	trace_mount \
	trace_oomkill \
	trace_open \
	trace_signal \
	trace_sni \
	trace_tcp \
	trace_tcpconnect \
	trace_tcpdrop \
	trace_tcpretrans \
	top_file \
	snapshot_process \
	snapshot_socket \
	ci/sched_cls_drop \
	#

.PHONY: all
all: build

build: $(GADGETS)

# GADGET_BUILD_PARAMS can be used to pass additional parameters:
#     GADGET_BUILD_PARAMS="--update-metadata" make build
# IG_ARTIFACTHUB_PKG_${FIELD} can be used to override custom fields:
#     IG_ARTIFACTHUB_PKG_VERSION="0.26.0" make build
.PHONY: $(GADGETS)
$(GADGETS):
	@echo "Building $@"
	@sudo -E \
		IG_EXPERIMENTAL=true \
		IG_ARTIFACTHUB_PKG_IMAGE=$(GADGET_REPOSITORY)/$@:latest \
		$(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		-t $(GADGET_REPOSITORY)/$@:$(GADGET_TAG) \
		$$GADGET_BUILD_PARAMS \
		$@

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		sudo -E IG_EXPERIMENTAL=true $(IG) image push $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG) || exit 1 ; \
	done

.PHONY:
clean:
	for GADGET in $(GADGETS); do \
		sudo -E IG_EXPERIMENTAL=true $(IG) image remove $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done
