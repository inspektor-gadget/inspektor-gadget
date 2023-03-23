include $(shell pwd)/../../../minikube.mk

DNSTESTER_IMAGE ?= "ghcr.io/inspektor-gadget/dnstester:latest"

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:


# build

build:
	make -C $(shell pwd)/../../.. ig

.PHONY: build-tests
build-tests:
	docker buildx build -t ig-tests -f ./../../../Dockerfiles/ig-tests.Dockerfile ../../../
	docker run --rm --entrypoint cat ig-tests ig-integration.test > ./ig-integration.test

# test

TEST_TARGETS = \
	test-docker \
	test-containerd \
	test-cri-o

.PHONY: test-all
test-all: $(TEST_TARGETS) test

test: test-$(CONTAINER_RUNTIME)

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestListContainers" CONTAINER_RUNTIME=containerd make -C integration/ig/k8s test
.PHONY: phony_explicit
test-%: build build-tests
	export MINIKUBE_PROFILE=minikube-$* && \
	echo "Checking minikube with profile $${MINIKUBE_PROFILE} is running ..." && \
	$(MINIKUBE) status -p $${MINIKUBE_PROFILE} -f {{.APIServer}} >/dev/null || (echo "Error: $${MINIKUBE_PROFILE} not running, exiting ..." && exit 1) && \
	echo "Preparing minikube with profile $${MINIKUBE_PROFILE} for testing ..." && \
	$(MINIKUBE) cp ../../../ig-linux-amd64 $${MINIKUBE_PROFILE}:/bin/ig >/dev/null && \
	$(MINIKUBE) ssh sudo chmod +x /bin/ig && \
	$(MINIKUBE) cp ig-integration.test $${MINIKUBE_PROFILE}:/bin/ig-integration.test >/dev/null && \
	$(MINIKUBE) ssh sudo chmod +x /bin/ig-integration.test && \
	rm ig-integration.test && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ln -sf /var/lib/minikube/binaries/$(KUBERNETES_VERSION)/kubectl /bin/kubectl" && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ln -sf /etc/kubernetes/admin.conf /root/.kube/config" && \
	echo "Running test in minikube with profile $${MINIKUBE_PROFILE} ..." && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ig-integration.test -test.v -integration -container-runtime $* -dnstester-image $(DNSTESTER_IMAGE) $${INTEGRATION_TESTS_PARAMS}"
