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

var (
	// flags
	fsslowerMinLatency uint
	fsslowerFilesystem string
)

var validFsSlowerFilesystems = []string{"btrfs", "ext4", "nfs", "xfs"}

var fsslowerCmd = &cobra.Command{
	Use:   "fsslower",
	Short: "Trace open, read, write and fsync operations slower than a threshold",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if fsslowerFilesystem == "" {
			return utils.WrapInErrMissingArgs("--filesystem")
		}

		found := false

		for _, val := range validFsSlowerFilesystems {
			if fsslowerFilesystem == val {
				found = true
				break
			}
		}

		if !found {
			return utils.WrapInErrInvalidArg("--type / -t",
				fmt.Errorf("%q is not a valid filesystem", fsslowerFilesystem))
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomFsslowerColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-16s %-6s %1s %-6s %-7s %-8s %s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"COMM", "PID", "T", "BYTES", "OFFSET", "LAT(ms)", "FILE")
		}

		config := &utils.TraceConfig{
			GadgetName:       "fsslower",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
			Parameters: map[string]string{
				"filesystem": fsslowerFilesystem,
				"minlatency": strconv.FormatUint(uint64(fsslowerMinLatency), 10),
			},
		}

		err := utils.RunTraceAndPrintStream(config, fsslowerTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	fsslowerCmd.Flags().UintVarP(
		&fsslowerMinLatency, "min", "m", types.MinLatencyDefault,
		"Min latency to trace, in ms",
	)
	fsslowerCmd.Flags().StringVarP(
		&fsslowerFilesystem, "type", "t", "",
		fmt.Sprintf("Which filesystem to trace: [%s]", strings.Join(validFsSlowerFilesystems, ", ")),
	)

	TraceCmd.AddCommand(fsslowerCmd)
	utils.AddCommonFlags(fsslowerCmd, &params)
}

func fsslowerTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	if e.Type == eventtypes.ERR || e.Type == eventtypes.WARN ||
		e.Type == eventtypes.DEBUG || e.Type == eventtypes.INFO {
		fmt.Fprintf(os.Stderr, "%s: node %q: %s", e.Type, e.Node, e.Message)
		return ""
	}

	if e.Type != eventtypes.NORMAL {
		return ""
	}

	// TODO: what to print in this case?
	if e.Bytes == math.MaxInt64 {
		e.Bytes = 0
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-16s %-6d %1s %-6d %-7d %-8.2f %s",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Comm, e.Pid, e.Op, e.Bytes, e.Offset, float64(e.Latency)/1000.0, e.File))
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%-16s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%-16s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%-16s", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%-16s", e.Container))
			case "comm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "pid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pid))
			case "t":
				sb.WriteString(fmt.Sprintf("%1s", e.Op))
			case "bytes":
				sb.WriteString(fmt.Sprintf("%-6d", e.Bytes))
			case "offset":
				sb.WriteString(fmt.Sprintf("%-7d", e.Offset))
			case "lat":
				sb.WriteString(fmt.Sprintf("%-8.2f", float64(e.Latency)/1000.0))
			case "file":
				sb.WriteString(fmt.Sprintf("%24s", e.File))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomFsslowerColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", "NAMESPACE"))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", "POD"))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", "CONTAINER"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-6s", "PID"))
		case "t":
			sb.WriteString(fmt.Sprintf("%1s", "T"))
		case "bytes":
			sb.WriteString(fmt.Sprintf("%-6s", "BYTES"))
		case "offset":
			sb.WriteString(fmt.Sprintf("%-7s", "OFFSET"))
		case "lat":
			sb.WriteString(fmt.Sprintf("%-8s", "LAT(ms)"))
		case "file":
			sb.WriteString(fmt.Sprintf("%24s", "FILE"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
