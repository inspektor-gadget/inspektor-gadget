module traceloop

go 1.22.8

toolchain go1.23.2

// Version doesn't matter because of the replace directive below.
require github.com/inspektor-gadget/inspektor-gadget v0.0.0

require github.com/cilium/ebpf v0.16.0

require (
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa // indirect
	golang.org/x/sys v0.27.0 // indirect
)

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../
