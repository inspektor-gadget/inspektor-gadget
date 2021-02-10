IMAGE_TAG=$(shell ../tools/image-tag branch)

TESTS_DOCKER_ARGS ?= "-e KUBECONFIG=/opt/kubeconfig/config -v $(HOME)/.kube:/opt/kubeconfig"

.PHONY: build
build:
	mkdir -p bin
	cp ../kubectl-gadget-linux-amd64 bin/kubectl-gadget
	docker build -t docker.io/kinvolk/gadgettest:$(IMAGE_TAG) -f Dockerfile .
	rm -f bin/kubectl-gadget

.PHONY: push
push:
	docker push docker.io/kinvolk/gadgettest:$(IMAGE_TAG)

.PHONY: test
test:
	if [ "x$(KUBECONFIG)" = "x" ] ; then \
		echo "Running tests without KUBECONFIG variable" ; \
		docker run -i \
			--net=host \
			$(TESTS_DOCKER_ARGS) \
			docker.io/kinvolk/gadgettest:$(IMAGE_TAG) ; \
	else \
		echo "Running tests with KUBECONFIG = $(KUBECONFIG)" ; \
		docker run -i \
			--net=host \
			-e KUBECONFIG=/opt/kubeconfig/$(shell basename "$(KUBECONFIG)") \
			-v $(shell dirname "$(KUBECONFIG)"):/opt/kubeconfig \
			docker.io/kinvolk/gadgettest:$(IMAGE_TAG) ; \
	fi
