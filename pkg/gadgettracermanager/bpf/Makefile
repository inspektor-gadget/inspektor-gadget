# Building the BPF code for the map

DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)
BUILDER_DOCKER_FILE?=bpf-builder.Dockerfile
BUILDER_DOCKER_IMAGE?=kinvolk/bpf-builder:ig-latest

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: pull-bpf-builder-image build-bpf-object

build-docker-image:
	$(SUDO) docker build -t $(BUILDER_DOCKER_IMAGE) -f $(BUILDER_DOCKER_FILE) .

pull-bpf-builder-image:
	$(SUDO) docker pull $(BUILDER_DOCKER_IMAGE)

build-bpf-object:
	$(SUDO) docker run -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		--rm -v $(PWD):/src:ro -v $(PWD)/out:/dist/ \
		--workdir=/src \
		$(BUILDER_DOCKER_IMAGE) \
		make -f bpf.mk build
	sudo chown -R $(UID):$(UID) out
	mv out/tracer-map-assets-bpf.go ./
	rm -f out/tracer-map.o
	rmdir out

clean:
	rm -f tracer-map-assets-bpf.go
