.PHONY: generated-files
generated-files: api/hook-service.pb.go

api/hook-service.pb.go: api/hook-service.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/hook-service.proto

clean:
	rm -f api/hook-service.pb.go api/hook-service_grpc.pb.go
