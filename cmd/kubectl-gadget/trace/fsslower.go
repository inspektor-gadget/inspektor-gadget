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
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/fsslower/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"github.com/spf13/cobra"
)

func newFsSlowerCmd() *cobra.Command {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -16,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"t":         -1,
		"bytes":     -6,
		"offset":    -7,
		"lat":       -8,
		"file":      -24,
	}

	defaultColumns := []string{
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
				return utils.WrapInErrMissingArgs("--filesystem / -f")
			}

			found := false
			for _, val := range validFsSlowerFilesystems {
				if fsslowerFilesystem == val {
					found = true
					break
				}
			}

			if !found {
				return utils.WrapInErrInvalidArg("--filesystem / -f",
					fmt.Errorf("%q is not a valid filesystem", fsslowerFilesystem))
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &utils.TraceConfig{
				GadgetName:       "fsslower",
				Operation:        "start",
				TraceOutputMode:  "Stream",
				TraceOutputState: "Started",
				CommonFlags:      &commonFlags,
				Parameters: map[string]string{
					"filesystem": fsslowerFilesystem,
					"minlatency": strconv.FormatUint(uint64(fsslowerMinLatency), 10),
				},
			}

			// print header
			var requestedColumns []string
			switch commonFlags.OutputMode {
			case utils.OutputModeJSON:
				// Nothing to print
			case utils.OutputModeColumns:
				requestedColumns = defaultColumns
			case utils.OutputModeCustomColumns:
				requestedColumns = commonFlags.CustomColumns
			}
			printColumnsHeader(columnsWidth, requestedColumns)

			transformEvent := func(line string) string {
				var e types.Event

				if err := json.Unmarshal([]byte(line), &e); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
					return ""
				}

				if e.Type != eventtypes.NORMAL {
					utils.ManageSpecialEvent(e.Event, commonFlags.Verbose)
					return ""
				}

				return fsslowerTransformLine(e, columnsWidth, requestedColumns)
			}

			if err := utils.RunTraceAndPrintStream(config, transformEvent); err != nil {
				return utils.WrapInErrRunGadget(err)
			}

			return nil
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

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

// fsslowerTransformLine is called to transform an event to columns format.
func fsslowerTransformLine(event types.Event, columnsWidth map[string]int, requestedColumns []string) string {
	var sb strings.Builder

	// TODO: what to print in this case?
	if event.Bytes == math.MaxInt64 {
		event.Bytes = 0
	}

	for _, col := range requestedColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.Container))
		case "pid":
			sb.WriteString(fmt.Sprintf("%*d", columnsWidth[col], event.Pid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.Comm))
		case "t":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.Op))
		case "bytes":
			sb.WriteString(fmt.Sprintf("%*d", columnsWidth[col], event.Bytes))
		case "offset":
			sb.WriteString(fmt.Sprintf("%*d", columnsWidth[col], event.Offset))
		case "lat":
			sb.WriteString(fmt.Sprintf("%*.2f", columnsWidth[col], float64(event.Latency)/1000.0))
		case "file":
			sb.WriteString(fmt.Sprintf("%*s", columnsWidth[col], event.File))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	return sb.String()
}
