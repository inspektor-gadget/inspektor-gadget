TINYGO ?= tinygo
TAR ?= tar

ARCHS = amd64 arm64
TARGETS = $(foreach ARCH,$(ARCHS),../help-$(ARCH).tar)

all: $(TARGETS)

../help-%.tar: help.go
	$(eval TMP := $(shell mktemp -d))
	GOARCH=$* $(TINYGO) build -no-debug -gc leaking -scheduler=none -panic=trap -o $(TMP)/help $^
	$(TAR) -C $(TMP) -cf $@ help
