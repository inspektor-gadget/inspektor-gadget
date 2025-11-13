.PHONY: generated-files
generated-files: api/api_grpc.pb.go

# Example of usage:
#   PROTOC=$HOME/.local/bin/protoc
PROTOC ?= protoc

api/api_grpc.pb.go: api/api.proto
	$(PROTOC) --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/api.proto

clean:
	rm -f api/api.pb.go api/api_grpc.pb.go
