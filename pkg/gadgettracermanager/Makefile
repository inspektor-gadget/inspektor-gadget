.PHONY: generated-files
generated-files: api/gadgettracermanager.pb.go

api/gadgettracermanager.pb.go: api/gadgettracermanager.proto
	protoc -I api/ api/gadgettracermanager.proto --go_out=plugins=grpc:api

clean:
	rm -f api/gadgettracermanager.pb.go
