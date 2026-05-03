module trace_grpc

go 1.25.7

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../

require (
	github.com/inspektor-gadget/inspektor-gadget v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.11
)
