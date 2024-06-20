module main

go 1.22.0

require (
	github.com/ghedo/go.pkt v0.0.0-20200209120728-c97f47ad982f
	github.com/inspektor-gadget/inspektor-gadget v0.27.0
)

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../
