CC = gcc
CFLAGS = -shared -fPIC -O2 -g
GO ?= go
#GOTOOLCHAIN ?= go1.20.14

all: libmylib.so godemo

libmylib.so: mylib.c
	$(CC) $(CFLAGS) -o $@ $<

godemo: main.go libmylib.so
ifdef GOTOOLCHAIN
	GOTOOLCHAIN=$(GOTOOLCHAIN) $(GO) build -gcflags="-N -l" -o $@ main.go
else
	$(GO) build -gcflags="-N -l" -o $@ main.go
endif

# Test targets
test: test-python

test-python: libmylib.so
	./pydemo.py

test-go: godemo
	./godemo

clean:
	rm -f libmylib.so godemo

clean-go:
	rm -f godemo

.PHONY: all clean test test-python test-go clean-go