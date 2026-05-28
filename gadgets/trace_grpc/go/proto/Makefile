# Makefile to regenerate FileDescriptorSet .pb files for proto-aware decoding.
#
# These .pb files are committed to the repo so that the WASM module can be
# built without needing protoc or the source .proto files. Regenerate only
# when updating to a newer proto version.
#
# Prerequisites:
#   - protoc (v28+)
#   - Source repos checked out at the paths below (or override via variables)

PROTOC ?= protoc
PROTOC_INCLUDE ?= $(dir $(PROTOC))../include

CRI_API ?= $(HOME)/go/src/github.com/kubernetes/cri-api/pkg/apis/runtime/v1
CONTAINERD_API ?= $(HOME)/go/src/github.com/containerd/containerd/api
GOOGLEAPIS ?= $(HOME)/go/src/github.com/googleapis/googleapis

.PHONY: all clean

all: cri.pb containerd.pb

cri.pb:
	$(PROTOC) --descriptor_set_out=$@ --include_imports \
		-I $(CRI_API) \
		$(CRI_API)/api.proto

containerd.pb:
	$(PROTOC) --descriptor_set_out=$@ --include_imports \
		-I $(CONTAINERD_API) \
		-I $(PROTOC_INCLUDE) \
		-I $(GOOGLEAPIS) \
		$$(find $(CONTAINERD_API)/services -name "*.proto") \
		$$(find $(CONTAINERD_API)/types -name "*.proto")

clean:
	rm -f cri.pb containerd.pb
