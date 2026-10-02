MINIKUBE_VERSION ?= v1.38.1
KUBERNETES_VERSION ?= v1.35.1
MINIKUBE_DRIVER ?= docker

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
MINIKUBE_DIR ?= $(PROJECT_DIR)/bin/minikube

CONTAINER_RUNTIME ?= docker

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

# minikube

MINIKUBE = $(MINIKUBE_DIR)/minikube-$(MINIKUBE_VERSION)
MINIKUBE_PROFILE_FLAGS = $(if $(MINIKUBE_PROFILE),--profile="$(MINIKUBE_PROFILE)")

.PHONY: minikube-install
minikube-install:
	mkdir -p $(MINIKUBE_DIR)
	test -e $(MINIKUBE_DIR)/minikube-$(MINIKUBE_VERSION) || \
	(cd $(MINIKUBE_DIR) && curl -Lo ./minikube-$(MINIKUBE_VERSION) https://github.com/kubernetes/minikube/releases/download/$(MINIKUBE_VERSION)/minikube-linux-$(shell go env GOHOSTARCH))
	chmod +x $(MINIKUBE_DIR)/minikube-$(MINIKUBE_VERSION)

.PHONY: minikube-host-ip
minikube-host-ip:
	@addresses="$$($(MINIKUBE) $(MINIKUBE_PROFILE_FLAGS) ssh -- 'getent ahostsv4 host.minikube.internal')" && \
		printf '%s\n' "$$addresses" | awk 'NR == 1 { print $$1 }'

.PHONY: minikube-image-load
minikube-image-load:
	@test -n "$(CONTAINER_IMAGE)" || { echo "CONTAINER_IMAGE is required" >&2; exit 1; }
	$(MINIKUBE) $(MINIKUBE_PROFILE_FLAGS) image load "$(CONTAINER_IMAGE)"

# clean

.PHONY: minikube-clean
minikube-clean:
	$(MINIKUBE) delete -p minikube-docker
	$(MINIKUBE) delete -p minikube-containerd
	$(MINIKUBE) delete -p minikube-cri-o
	rm -rf $(MINIKUBE_DIR)

# start

MINIKUBE_START_TARGETS = \
	minikube-start-docker \
	minikube-start-containerd \
	minikube-start-cri-o

.PHONY: minikube-start-all
minikube-start-all: $(MINIKUBE_START_TARGETS)

minikube-start: minikube-start-$(CONTAINER_RUNTIME)

.PHONY: phony_explicit
minikube-start-%: minikube-install
	$(MINIKUBE) status -p minikube-$* -f {{.APIServer}} >/dev/null || \
	$(MINIKUBE) start -p minikube-$* --driver=$(MINIKUBE_DRIVER) --kubernetes-version=$(KUBERNETES_VERSION) --container-runtime=$* --wait=all $${MINIKUBE_PARAMS}
	$(MINIKUBE) profile minikube-$*
