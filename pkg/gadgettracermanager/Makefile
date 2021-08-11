.PHONY: generated-files
generated-files: api/gadgettracermanager.pb.go

api/gadgettracermanager.pb.go: api/gadgettracermanager.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/gadgettracermanager.proto

clean:
	rm -f api/gadgettracermanager.pb.go api/gadgettracermanager_grpc.pb.go
