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

package trace

import (
	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontrace "github.com/kinvolk/inspektor-gadget/cmd/common/trace"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	execTracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	execTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

func newExecCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(*cobra.Command, []string) error {
		ExecGadget := &TraceGadget[execTypes.Event]{
			commonFlags: &commonFlags,
			parser:      commontrace.NewExecParserWithRuntimeInfo(&commonFlags.OutputConfig),
			createAndRunTracer: func(mountnsmap *ebpf.Map, enricher gadgets.DataEnricher, eventCallback func(execTypes.Event)) (trace.Tracer, error) {
				return execTracer.NewTracer(&execTracer.Config{MountnsMap: mountnsmap}, enricher, eventCallback)
			},
		}

		return ExecGadget.Run()
	}

	cmd := commontrace.NewExecCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
