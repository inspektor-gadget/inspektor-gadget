CC = gcc
CFLAGS = -shared -fPIC -O2 -g
GO ?= go
#GOTOOLCHAIN ?= go1.20.14

# This path must match the SEC("uprobe/...") annotations in program.bpf.c
INSTALL_DIR = /tmp/ig-tests/ci-stacks-workload

all: libmylib.so godemo

libmylib.so: mylib.c
	$(CC) $(CFLAGS) -o $@ $<

godemo: main.go libmylib.so
ifdef GOTOOLCHAIN
	GOTOOLCHAIN=$(GOTOOLCHAIN) $(GO) build -gcflags="-N -l" -o $@ main.go
else
	$(GO) build -gcflags="-N -l" -o $@ main.go
endif

install: libmylib.so
	mkdir -p $(INSTALL_DIR)
	ln -sf $(CURDIR)/libmylib.so $(INSTALL_DIR)/libmylib.so

# Test targets
test: test-python

test-python: install
	./pydemo.py

test-go: install godemo
	./godemo

clean:
	rm -f libmylib.so godemo
	rm -f $(INSTALL_DIR)/libmylib.so

clean-go:
	rm -f godemo

.PHONY: all clean test test-python test-go clean-go install