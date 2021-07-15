TEST_ASSETS=$(PWD)/bin
OS_NAME := $(shell uname -s | tr A-Z a-z)
ARCH ?= amd64

# download etcd
etcd:
ifeq (, $(wildcard $(TEST_ASSETS)/etcd))
	@{ \
	set -xe ;\
	INSTALL_TMP_DIR=$$(mktemp -d) ;\
	cd $$INSTALL_TMP_DIR ;\
	GOOGLE_URL=https://storage.googleapis.com/etcd ;\
	GITHUB_URL=https://github.com/etcd-io/etcd/releases/download ;\
	DOWNLOAD_URL=$${GITHUB_URL} ;\
	ETCD_VER=v3.5.0 ;\
	wget $${DOWNLOAD_URL}/$${ETCD_VER}/etcd-$${ETCD_VER}-$(OS_NAME)-$(ARCH).tar.gz ;\
	SHA256SUM=864baa0437f8368e0713d44b83afe21dce1fb4ee7dae4ca0f9dd5f0df22d01c4 ;\
	sha256sum etcd-$${ETCD_VER}-$(OS_NAME)-$(ARCH).tar.gz | grep -q $$SHA256SUM ;\
	mkdir -p $(TEST_ASSETS) ;\
	tar zxvf etcd-$${ETCD_VER}-$(OS_NAME)-$(ARCH).tar.gz ;\
	mv etcd-$${ETCD_VER}-$(OS_NAME)-$(ARCH)/etcd $(TEST_ASSETS)/ ;\
	rm -rf $$INSTALL_TMP_DIR ;\
	}
ETCD_BIN=$(TEST_ASSETS)/etcd
else
ETCD_BIN=$(TEST_ASSETS)/etcd
endif

# download kube-apiserver
kube-apiserver:
ifeq (, $(wildcard $(TEST_ASSETS)/kube-apiserver))
	@{ \
	set -xe ;\
	INSTALL_TMP_DIR=$$(mktemp -d) ;\
	cd $$INSTALL_TMP_DIR ;\
	VER=v1.21.2 ;\
	DOWNLOAD_URL=https://dl.k8s.io/$$VER/bin/$(OS_NAME)/$(ARCH)/kube-apiserver ;\
	wget $${DOWNLOAD_URL} ;\
	SHA256SUM=04de7369c4e80eaaf8da440dcf62e050e908d786ac8b3248585dbe659c06d769 ;\
	sha256sum kube-apiserver | grep -q $$SHA256SUM ;\
	mkdir -p $(TEST_ASSETS) ;\
	chmod +x kube-apiserver ;\
	mv kube-apiserver $(TEST_ASSETS)/ ;\
	rm -rf $$INSTALL_TMP_DIR ;\
	}
KUBE_APISERVER_BIN=$(TEST_ASSETS)/kube-apiserver
else
KUBE_APISERVER_BIN=$(TEST_ASSETS)/kube-apiserver
endif

# download kubectl
kubectl:
ifeq (, $(wildcard $(TEST_ASSETS)/kubectl))
	@{ \
	set -xe ;\
	INSTALL_TMP_DIR=$$(mktemp -d) ;\
	cd $$INSTALL_TMP_DIR ;\
	VER=v1.21.2 ;\
	DOWNLOAD_URL=https://dl.k8s.io/$$VER/bin/$(OS_NAME)/$(ARCH)/kubectl ;\
	wget $${DOWNLOAD_URL} ;\
	SHA256SUM=55b982527d76934c2f119e70bf0d69831d3af4985f72bb87cd4924b1c7d528da ;\
	sha256sum kubectl | grep -q $$SHA256SUM ;\
	mkdir -p $(TEST_ASSETS) ;\
	chmod +x kubectl ;\
	mv kubectl $(TEST_ASSETS)/ ;\
	rm -rf $$INSTALL_TMP_DIR ;\
	}
KUBECTL_BIN=$(TEST_ASSETS)/kubectl
else
KUBECTL_BIN=$(TEST_ASSETS)/kubectl
endif

