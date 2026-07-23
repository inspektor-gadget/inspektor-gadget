// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// WASM pre-start module for trace_gpu_starvation.
//
// The gadget hooks finish_task_switch with a kprobe, but on most x86_64
// kernels the compiler emits that function as a specialized clone named
// "finish_task_switch.isra.0" (the suffix number and kind depend on the
// kernel build; arm64 kernels usually keep the plain name). cilium/ebpf's
// link.Kprobe only retries with the arch syscall prefix, not compiler
// suffixes, so attaching to the bare name fails on those kernels.
//
// Resolve the real symbol at start-up (like gadgets/fsnotify does for its
// renamed hooks) and point the program's attach_to at whichever candidate
// exists in /proc/kallsyms.
package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Program name of the kprobe, i.e. the C function passed to BPF_KPROBE()
// in program.bpf.c. Used to build the "programs.<name>.attach_to" config key.
const kprobeProgramName = "ig_finish_task_switch"

// Candidate symbols for finish_task_switch, in order of likelihood. Each
// api.KallsymsSymbolExists() call scans all of /proc/kallsyms (a miss scans
// the whole file), so the most probable symbol must come first to minimize
// work. On x86_64 kernels -- which GPU nodes overwhelmingly are -- the
// compiler specializes it to "finish_task_switch.isra.0"; the plain name is
// mainly arm64 and older/x86 builds; the remaining suffixes are rare.
var finishTaskSwitchCandidates = []string{
	"finish_task_switch.isra.0",
	"finish_task_switch",
	"finish_task_switch.constprop.0",
	"finish_task_switch.isra.0.constprop.0",
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	for _, sym := range finishTaskSwitchCandidates {
		if api.KallsymsSymbolExists(sym) {
			api.SetConfig("programs."+kprobeProgramName+".attach_to", sym)
			return 0
		}
	}

	api.Errorf("kernel symbol not found: finish_task_switch (or a .isra/.constprop specialization)")
	return 1
}

func main() {}
