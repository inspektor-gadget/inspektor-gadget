SHELL := /bin/bash

GADGETS_TAG ?= $(shell ../tools/image-tag branch)
GADGETS_REPOSITORY ?= ghcr.io/inspektor-gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder:latest

GADGETS = \
	trace_dns \
	trace_exec \
	trace_open \
	trace_tcpconnect \
	trace_tcpretrans \
	#

.PHONY: all
all: $(GADGETS)

#TODO: How to create an independent target for each gadget do this can be run in parallel?
.PHONY:
build:
	@echo "Building all gadgets"
	@for GADGET in $(GADGETS); do \
		CATEGORY=$$(echo $$GADGET | cut -d_ -f1) && \
		NAME=$$(echo $$GADGET | cut -d_ -f2) && \
		pushd $$CATEGORY/$$NAME/ && \
		IG_EXPERIMENTAL=true ig image build --builder-image $(BUILDER_IMAGE) \
			$(GADGETS_REPOSITORY)/$$GADGET:$(GADGETS_TAG) &&  \
		popd; \
	done

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		IG_EXPERIMENTAL=true ig image push $(GADGETS_REPOSITORY)/$$GADGET:$(GADGETS_TAG); \
	done
