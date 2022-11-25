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

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	mountTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/tracer"
	mountTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
)

func newMountCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(*cobra.Command, []string) error {
		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, mountTypes.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		mountGadget := &TraceGadget[mountTypes.Event]{
			commonFlags: &commonFlags,
			parser:      parser,
			createAndRunTracer: func(mountnsmap *ebpf.Map, enricher gadgets.DataEnricherByMntNs, eventCallback func(mountTypes.Event)) (trace.Tracer, error) {
				return mountTracer.NewTracer(&mountTracer.Config{MountnsMap: mountnsmap}, enricher, eventCallback)
			},
		}

		return mountGadget.Run()
	}

	cmd := commontrace.NewMountCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
