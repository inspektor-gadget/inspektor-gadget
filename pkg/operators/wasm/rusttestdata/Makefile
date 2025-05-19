ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
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
#

all: $(TEST_ARTIFACTS)

# Build images, run 'ig image list' to check built images
.PHONY: $(TEST_ARTIFACTS)

$(TEST_ARTIFACTS):
@echo "Building $@"
@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest $@
