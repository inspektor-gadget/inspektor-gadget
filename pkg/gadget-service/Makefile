.PHONY: generated-files
generated-files: api/gadgettracermanager.pb.go

api/gadgettracermanager.pb.go: api/api.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/api.proto

clean:
	rm -f api/api.pb.go api/api_grpc.pb.go
