module main

go 1.24.0

// Version doesn't matter because of the replace directive below.
require github.com/inspektor-gadget/inspektor-gadget v0.0.0

require (
	github.com/opencontainers/runtime-spec v1.2.1
	golang.org/x/sys v0.33.0
)

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../
