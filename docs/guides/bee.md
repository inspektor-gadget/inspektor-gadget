make -C examples/gadgets/bee
go run -exec sudo ./cmd/local-gadget/... -r docker trace bee --file=examples/gadgets/bee/dns_bpfel.o
