// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this ebpf except in compliance with the License.
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
)

func newEbpfCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontop.CommonTopFlags

	cols := types.GetColumns()

	cmd := commontop.NewEbpfCmd(func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		gadget := &TopGadget[types.Stats, gadgets.DataNodeEnricher]{
			TopGadget: commontop.TopGadget[types.Stats]{
				CommonTopFlags: &flags,
				OutputConfig:   &commonFlags.OutputConfig,
				Parser:         parser,
				ColMap:         cols.ColumnMap,
			},
			commonFlags: &commonFlags,
			createAndRunTracer: func(mountNsMap *ebpf.Map, enricher gadgets.DataNodeEnricher, eventCallback func(*top.Event[types.Stats])) (trace.Tracer, error) {
				config := &tracer.Config{
					MaxRows:  flags.MaxRows,
					Interval: time.Second * time.Duration(flags.OutputInterval),
					SortBy:   flags.ParsedSortBy,
				}

				return tracer.NewTracer(config, gadgets.DataNodeEnricher(enricher), eventCallback)
			},
		}

		return gadget.Run(args)
	})

	commontop.AddCommonTopFlags(cmd, &flags, cols.ColumnMap, types.SortByDefault)
	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
