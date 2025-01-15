module traceloop

go 1.23.0

toolchain go1.23.4

// Version doesn't matter because of the replace directive below.
require github.com/inspektor-gadget/inspektor-gadget v0.0.0

require golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c // indirect

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../
