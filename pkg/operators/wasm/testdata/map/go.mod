module main

go 1.22.7

require github.com/inspektor-gadget/inspektor-gadget v0.27.0

require (
	github.com/cilium/ebpf v0.16.0 // indirect
	golang.org/x/exp v0.0.0-20240808152545-0cdaa3abc0fa // indirect
	golang.org/x/sys v0.26.0 // indirect
)

// use this to be able to compile it locally
replace github.com/inspektor-gadget/inspektor-gadget => ../../../../../
