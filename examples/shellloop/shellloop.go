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
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"
	traceloopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
)

const traceName = "trace_exec"

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	tracer, err := tracer.NewTracer(nil)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()

	runtime.LockOSThread()
	err = unix.Unshare(syscall.CLONE_NEWNS)
	if err != nil {
		fmt.Printf("error creating new mount namespace: %s\n", err)
		return
	}

	fileinfo, err := os.Stat("/proc/thread-self/ns/mnt")
	if err != nil {
		fmt.Printf("error opening proc file: %s\n", err)
		return
	}

	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if err != nil {
		fmt.Printf("error reading : %s\n", err)
		return
	}
	if !ok {
		fmt.Printf("error reading file\n")
		return
	}
	mntns := stat.Ino

	err = tracer.Attach("shell", mntns)

	cmd := exec.Command("sh")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Printf("error executing command : %s\n", err)
	}

	events, err := tracer.Read("shell")
	if err != nil {
		fmt.Printf("error reading events: %s\n", err)
		return
	}

	columns := traceloopTypes.GetColumns()

	var commonFlags utils.CommonFlags
	parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, columns)
	if err != nil {
		fmt.Printf("error getting parser: %s\n", err)
		return
	}

	fmt.Println(parser.BuildColumnsHeader())
	for _, event := range events {
		if event.Comm == "shellloop" {
			continue
		}
		line := parser.TransformIntoColumns(event)
		fmt.Println(line)
	}
}
