module trace_dns

go 1.22.8

require (
	// Version doesn't matter because of the replace directive below.
	github.com/inspektor-gadget/inspektor-gadget v0.0.0
	golang.org/x/net v0.30.0
)

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../
