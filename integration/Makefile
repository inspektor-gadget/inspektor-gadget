CONTAINER_REPO ?= ghcr.io/kinvolk/inspektor-gadget
TEST_CONTAINER_REPO ?= $(CONTAINER_REPO)-test
IMAGE_TAG ?= $(shell ../tools/image-tag branch)

TESTS_DOCKER_ARGS ?= -e KUBECONFIG=/opt/kubeconfig/config -v $(HOME)/.kube:/opt/kubeconfig

KUBERNETES_DISTRIBUTION ?= ""

.PHONY: build
build:
	mkdir -p bin
	cp ../kubectl-gadget-linux-amd64 bin/kubectl-gadget
	docker build -t $(TEST_CONTAINER_REPO):$(IMAGE_TAG) -f Dockerfile \
		--build-arg KUBERNETES_DISTRIBUTION=$(KUBERNETES_DISTRIBUTION) .
	rm -f bin/kubectl-gadget

.PHONY: push
push:
	docker push $(TEST_CONTAINER_REPO):$(IMAGE_TAG)

.PHONY: test
test:
	if [ "x$(KUBECONFIG)" = "x" ] ; then \
		echo "Running tests without KUBECONFIG variable" ; \
		docker run --rm -i \
			--net=host \
			--name ig-integration-tests \
			$(TESTS_DOCKER_ARGS) \
			$(TEST_CONTAINER_REPO):$(IMAGE_TAG) ; \
	else \
		echo "Running tests with KUBECONFIG = $(KUBECONFIG)" ; \
		docker run --rm -i \
			--net=host \
			--name ig-integration-tests \
			-e KUBECONFIG=/opt/kubeconfig/$(shell basename "$(KUBECONFIG)") \
			-v $(shell dirname "$(KUBECONFIG)"):/opt/kubeconfig \
			$(TEST_CONTAINER_REPO):$(IMAGE_TAG) ; \
	fi
