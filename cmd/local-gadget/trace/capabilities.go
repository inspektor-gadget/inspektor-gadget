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
	capabilitiesTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	capabilitiesTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
)

func newCapabilitiesCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontrace.CapabilitiesFlags

	runCmd := func(*cobra.Command, []string) error {
		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(
			&commonFlags.OutputConfig,
			capabilitiesTypes.GetColumns(),
		)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		capabilitiesGadget := &TraceGadget[capabilitiesTypes.Event]{
			commonFlags: &commonFlags,
			parser:      parser,
			createAndRunTracer: func(mountnsmap *ebpf.Map, enricher gadgets.DataEnricherByMntNs, eventCallback func(*capabilitiesTypes.Event)) (trace.Tracer, error) {
				config := &capabilitiesTracer.Config{
					MountnsMap: mountnsmap,
					AuditOnly:  flags.AuditOnly,
					Unique:     flags.Unique,
				}

				return capabilitiesTracer.NewTracer(config, enricher, eventCallback)
			},
		}

		return capabilitiesGadget.Run()
	}

	cmd := commontrace.NewCapabilitiesCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
