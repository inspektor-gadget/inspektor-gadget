module main

go 1.23.0

// Version doesn't matter because of the replace directive below.
require github.com/inspektor-gadget/inspektor-gadget v0.0.0

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../
