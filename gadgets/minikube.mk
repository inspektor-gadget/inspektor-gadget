MINIKUBE_IP = $(shell $(MINIKUBE) ip)
MINIKUBE_REGISTRY = $(MINIKUBE_IP):5000

include ../minikube.mk

.PHONY: minikube-registry-enable
minikube-registry-enable:
	@echo "Enabling minikube registry addon"
	$(MINIKUBE) addons enable registry

.PHONY: minikube-registry-disable
minikube-registry-disable:
	@echo "Disabling minikube registry addon"
	$(MINIKUBE) addons disable registry

.PHONY: minikube-registry-enable
minikube-registry-prepare: minikube-registry-enable
	@echo "Pushing gadget images to minikube registry"
	$(MAKE) GADGET_REPOSITORY=$(MINIKUBE_REGISTRY) IG_FLAGS="--insecure-registries $(MINIKUBE_REGISTRY)" push-existing

# GADGET_PARAMS can be used to pass extra parameters to the gadget run command
# GADGET_PARAMS="--timeout 10" make -C gadgets GADGETS=trace_dns minikube-gadget-run
.PHONY:
minikube-gadget-run: minikube-registry-prepare
	@echo "Running gadgets on minikube"
	../kubectl-gadget run $(MINIKUBE_REGISTRY)/$(firstword $(GADGETS)):$(GADGET_TAG) --pull always $$GADGET_PARAMS
