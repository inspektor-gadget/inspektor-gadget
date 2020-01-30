.PHONY: generated-files
generated-files: api/gadgettracermanager.pb.go tracer-map-assets-bpf.go

api/gadgettracermanager.pb.go: api/gadgettracermanager.proto
	protoc -I api/ api/gadgettracermanager.proto --go_out=plugins=grpc:api

.PHONY: tracer-map-assets-bpf.go
tracer-map-assets-bpf.go:
	make -C bpf
	cp bpf/tracer-map-assets-bpf.go ./tracer-map-assets-bpf.go
	make -C bpf clean

clean:
	rm -f api/gadgettracermanager.pb.go tracer-map-assets-bpf.go
