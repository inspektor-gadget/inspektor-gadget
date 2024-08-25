package uprobetracer

// Keep sync with pkg/uprobetracer/bpf/usdt_helper.bpf.c
var registerEncoding = map[string]uint64{
	"zero":    0,
	"r15":     1,
	"r14":     2,
	"r13":     3,
	"r12":     4,
	"rbp":     5,
	"rbx":     6,
	"r11":     7,
	"r10":     8,
	"r9":      9,
	"r8":      10,
	"rax":     11,
	"rcx":     12,
	"rdx":     13,
	"rsi":     14,
	"rdi":     15,
	"orig_ax": 16,
	"rip":     17,
	"cs":      18,
	"flags":   19,
	"rsp":     20,
	"ss":      21,
}
