.PHONY: generated-files
generated-files: api/gadgettracermanager.pb.go api/gadgettracermanager_pb2.py tracer-map-assets-bpf.go

api/gadgettracermanager.pb.go: api/gadgettracermanager.proto
	protoc -I api/ api/gadgettracermanager.proto --go_out=plugins=grpc:api

api/gadgettracermanager_pb2.py: api/gadgettracermanager.proto
	/bin/rm -rf tmp-venv
	virtualenv tmp-venv
	source ./tmp-venv/bin/activate && pip install grpcio-tools
	source ./tmp-venv/bin/activate && python3 -m grpc_tools.protoc -Iapi --python_out=api --grpc_python_out=api api/gadgettracermanager.proto
	/bin/rm -rf tmp-venv

.PHONY: tracer-map-assets-bpf.go
tracer-map-assets-bpf.go:
	make -C bpf
	cp bpf/tracer-map-assets-bpf.go ./tracer-map-assets-bpf.go
	make -C bpf clean

clean:
	rm -f api/gadgettracermanager.pb.go tracer-map-assets-bpf.go
