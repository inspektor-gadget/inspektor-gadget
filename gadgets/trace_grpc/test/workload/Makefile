# This path must match the SEC("uprobe/...") annotation in program.bpf.c
INSTALL_DIR = /tmp/ig-tests/trace-grpc-workload
GO ?= go
BINARY = client

all: $(BINARY)

$(BINARY): main.go proto/greeter.pb.go proto/greeter_grpc.pb.go
	$(GO) mod tidy
	$(GO) build -gcflags="-N -l" -o $@ .

# Build a stripped binary (like kubelet in production)
stripped: main.go proto/greeter.pb.go proto/greeter_grpc.pb.go
	$(GO) mod tidy
	$(GO) build -ldflags="-s -w" -o $(BINARY) .

proto/greeter.pb.go proto/greeter_grpc.pb.go: proto/greeter.proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/greeter.proto
	$(GO) mod tidy

install: $(BINARY)
	mkdir -p $(INSTALL_DIR)
	ln -sf $(CURDIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)

run: install
	./$(BINARY)

clean:
	rm -f $(BINARY)
	rm -f $(INSTALL_DIR)/$(BINARY)

.PHONY: all clean install run stripped
