// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this tcp except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package top

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
)

func newTCPCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontop.TCPFlags

	cols := types.GetColumns()

	cmd := commontop.NewTCPCmd(func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		targetPid := int32(-1)
		if flags.FilteredPid != 0 {
			targetPid = int32(flags.FilteredPid)
		}

		targetFamily := int32(-1)
		if flags.Family != 0 {
			targetFamily = int32(flags.Family)
		}

		gadget := &TopGadget[types.Stats]{
			TopGadget: commontop.TopGadget[types.Stats]{
				CommonTopFlags: &flags.CommonTopFlags,
				OutputConfig:   &commonFlags.OutputConfig,
				Parser:         parser,
				ColMap:         cols.ColumnMap,
			},
			commonFlags: &commonFlags,
			createAndRunTracer: func(mountNsMap *ebpf.Map, enricher gadgets.DataEnricherByMntNs, eventCallback func(*top.Event[types.Stats])) (trace.Tracer, error) {
				config := &tracer.Config{
					MaxRows:      flags.MaxRows,
					Interval:     time.Second * time.Duration(flags.OutputInterval),
					SortBy:       flags.ParsedSortBy,
					MountnsMap:   mountNsMap,
					TargetPid:    targetPid,
					TargetFamily: targetFamily,
				}

				return tracer.NewTracer(config, enricher, eventCallback)
			},
		}

		return gadget.Run(args)
	}, &flags)

	commontop.AddCommonTopFlags(cmd, &flags.CommonTopFlags, cols.ColumnMap, types.SortByDefault)
	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
