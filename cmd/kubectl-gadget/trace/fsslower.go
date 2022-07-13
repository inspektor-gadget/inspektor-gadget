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
	"fmt"
	"math"
	"strconv"
	"strings"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/fsslower/types"

	"github.com/spf13/cobra"
)

type FsslowerParser struct {
	commonutils.BaseParser
}

func newFsSlowerCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"node",
				"namespace",
				"pod",
				"container",
				"pid",
				"comm",
				"t",
				"bytes",
				"offset",
				"lat",
				"file",
			},
		},
	}

	var (
		// flags
		fsslowerMinLatency uint
		fsslowerFilesystem string
	)

	validFsSlowerFilesystems := []string{"btrfs", "ext4", "nfs", "xfs"}

	cmd := &cobra.Command{
		Use:   "fsslower",
		Short: "Trace open, read, write and fsync operations slower than a threshold",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if fsslowerFilesystem == "" {
				return commonutils.WrapInErrMissingArgs("--filesystem / -f")
			}

			found := false
			for _, val := range validFsSlowerFilesystems {
				if fsslowerFilesystem == val {
					found = true
					break
				}
			}

			if !found {
				return commonutils.WrapInErrInvalidArg("--filesystem / -f",
					fmt.Errorf("%q is not a valid filesystem", fsslowerFilesystem))
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fsslowerGadget := &TraceGadget[types.Event]{
				name:        "fsslower",
				commonFlags: commonFlags,
				parser:      NewFsslowerParser(&commonFlags.OutputConfig),
				params: map[string]string{
					"filesystem": fsslowerFilesystem,
					"minlatency": strconv.FormatUint(uint64(fsslowerMinLatency), 10),
				},
			}

			return fsslowerGadget.Run()
		},
	}

	cmd.Flags().UintVarP(
		&fsslowerMinLatency, "min", "m", types.MinLatencyDefault,
		"Min latency to trace, in ms",
	)
	cmd.Flags().StringVarP(
		&fsslowerFilesystem, "filesystem", "f", "",
		fmt.Sprintf("Which filesystem to trace: [%s]", strings.Join(validFsSlowerFilesystems, ", ")),
	)

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func NewFsslowerParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"t":         -1,
		"bytes":     -6,
		"offset":    -7,
		"lat":       -8,
		"file":      -24,
	}

	return &FsslowerParser{
		BaseParser: commonutils.BaseParser{
			ColumnsWidth: columnsWidth,
			OutputConfig: outputConfig,
		},
	}
}

func (p *FsslowerParser) TransformEvent(event *types.Event, requestedColumns []string) string {
	var sb strings.Builder

	// TODO: what to print in this case?
	if event.Bytes == math.MaxInt64 {
		event.Bytes = 0
	}

	for _, col := range requestedColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Container))
		case "pid":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Pid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Comm))
		case "t":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Op))
		case "bytes":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Bytes))
		case "offset":
			sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Offset))
		case "lat":
			sb.WriteString(fmt.Sprintf("%*.2f", p.ColumnsWidth[col], float64(event.Latency)/1000.0))
		case "file":
			sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.File))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
