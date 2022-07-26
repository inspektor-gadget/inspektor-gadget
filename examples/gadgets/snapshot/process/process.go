// Copyright 2022 The Inspektor Gadget authors
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

package main

import (
	"fmt"

	"github.com/cilium/ebpf/rlimit"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
)

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	processes, err := tracer.RunCollector(nil, nil)
	if err != nil {
		fmt.Printf("error running collector: %s\n", err)
		return
	}

	fmt.Printf("%-16s %7s\n", "NAME", "PID")
	for _, process := range processes {
		fmt.Printf("%-16s %7d\n", process.Command, process.Pid)
	}
}
