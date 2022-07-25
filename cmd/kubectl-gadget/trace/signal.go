// Copyright 2019-2022 The Inspektor Gadget authors
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
	"strconv"
	"strings"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/sigsnoop/types"

	"github.com/spf13/cobra"
)

type SignalParser struct {
	commonutils.BaseParser[types.Event]
}

func newSignalCmd() *cobra.Command {
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
				"signal",
				"tpid",
				"ret",
			},
		},
	}

	var (
		// flags
		pid    uint
		sig    string
		failed bool
	)

	cmd := &cobra.Command{
		Use:   "signal",
		Short: "Trace signals received by processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			signalGadget := &TraceGadget[types.Event]{
				name:        "sigsnoop",
				commonFlags: commonFlags,
				parser:      NewSignalParser(&commonFlags.OutputConfig),
				params: map[string]string{
					"signal": sig,
					"pid":    strconv.FormatUint(uint64(pid), 10),
					"failed": strconv.FormatBool(failed),
				},
			}

			return signalGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)

	cmd.PersistentFlags().UintVarP(
		&pid,
		"pid",
		"",
		0,
		"Show only signal sent by this particular PID",
	)
	cmd.PersistentFlags().StringVarP(
		&sig,
		"signal",
		"",
		"",
		`Trace only this signal (it can be an int like 9 or string beginning with "SIG" like "SIGKILL")`,
	)
	cmd.PersistentFlags().BoolVarP(
		&failed,
		"failed-only",
		"f",
		false,
		`Show only events where the syscall sending a signal failed`,
	)

	return cmd
}

func NewSignalParser(outputConfig *commonutils.OutputConfig) TraceParser[types.Event] {
	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"signal":    -16,
		"tpid":      -6,
		"ret":       -6,
	}

	return &SignalParser{
		BaseParser: commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
	}
}

func (p *SignalParser) TransformEvent(event *types.Event) string {
	return p.Transform(event, func(event *types.Event) string {
		var sb strings.Builder

		for _, col := range p.OutputConfig.CustomColumns {
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
			case "signal":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], event.Signal))
			case "tpid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.TargetPid))
			case "ret":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], event.Retval))
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
