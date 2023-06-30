// Copyright 2023 The Inspektor Gadget authors
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
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestRunTraceOpen(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-open")

	t.Parallel()

	if *k8sArch == "arm64" {
		t.Skip("Skip running run trace open on arm64 as run gadget does not filter out non existing tracepoints")
	}

	const (
		prog = "../../gadgets/trace_open_x86.bpf.o"
		def  = "../../gadgets/trace_open.yaml"
	)

	traceOpenCmd := &Command{
		Name:         "StartRunTraceOpenGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET run --prog @%s --definition @%s -n %s -o json", prog, def, ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEntry := &types.Event{
				Event: BuildBaseEvent(ns),
				Data: map[string]interface{}{
					"comm":      "cat",
					"fname":     "/dev/null",
					"uid":       uint32(1000),
					"gid":       uint32(1111),
					"ret":       3,
					"flags":     0,
					"mode":      uint16(0),
					"mntns_id":  uint64(0),
					"pid":       uint32(0),
					"timestamp": uint64(0),
				},
			}

			normalize := func(e *types.Event) {
				e.Timestamp = 0
				e.Node = ""
				e.MountNsID = 0
				e.RawData = nil
				data := e.Data.(map[string]interface{})
				if data == nil {
					return
				}
				data["pid"] = uint32(0)
				data["mntns_id"] = uint64(0)
				data["timestamp"] = uint64(0)

				// TODO: find better way
				// json unmarshalling always uses float64 for numbers
				data["ret"] = int(data["ret"].(float64))
				data["flags"] = int(data["flags"].(float64))
				data["mode"] = uint16(data["mode"].(float64))
				data["uid"] = uint32(data["uid"].(float64))
				data["gid"] = uint32(data["gid"].(float64))
			}

			return ExpectEntriesToMatch(output, normalize, expectedEntry)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceOpenCmd,
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 cat /dev/null"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
