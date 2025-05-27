ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/gadget-builder:main
IG ?= ig

TEST_ARTIFACTS = \
params \
config \
map \
mapofmap \
perf \
syscall \
kallsyms \
filtering \
baderrptr \
dataemit
#

all: $(TEST_ARTIFACTS)

# Build images, run 'ig image list' to check built images
.PHONY: $(TEST_ARTIFACTS)

$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build --builder-image $(BUILDER_IMAGE) --builder-image-pull=never -t $@:latest $@
	@sudo $(IG) image export $@:latest $@.tar
