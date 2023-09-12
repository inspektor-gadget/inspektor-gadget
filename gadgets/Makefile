SHELL := /bin/bash

GADGETS_TAG ?= $(shell ../tools/image-tag branch)
GADGETS_REPOSITORY ?= ghcr.io/inspektor-gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder:latest
IG ?= ig
GADGETS = \
	trace_dns \
	trace_exec \
	trace_open \
	trace_tcpconnect \
	trace_tcpretrans \
	#

.PHONY: all
all: build

build: $(GADGETS)

.PHONY: $(GADGETS)
$(GADGETS):
	@echo "Building $@"
	@sudo IG_EXPERIMENTAL=true $(IG) image build --builder-image $(BUILDER_IMAGE) \
		-t $(GADGETS_REPOSITORY)/$@:$(GADGETS_TAG) $@

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		sudo IG_EXPERIMENTAL=true $(IG) image push $(GADGETS_REPOSITORY)/$$GADGET:$(GADGETS_TAG); \
	done