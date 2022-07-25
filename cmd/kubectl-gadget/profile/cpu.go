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

package profile

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/types"
)

type CPUFlags struct {
	profileKernelOnly bool
	profileUserOnly   bool
}

type CPUParser struct {
	commonutils.BaseParser[types.Report]

	cpuFlags *CPUFlags
}

func newCPUCmd() *cobra.Command {
	var cpuFlags CPUFlags

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
				"count",
				"stack",
			},
		},
	}

	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"count":     -6,
		"stack":     -30,
	}

	cmd := &cobra.Command{
		Use:          "cpu",
		Short:        "Analyze CPU performance by sampling stack traces",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if cpuFlags.profileUserOnly && cpuFlags.profileKernelOnly {
				return commonutils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			params := map[string]string{}
			if cpuFlags.profileUserOnly {
				params[types.ProfileUserParam] = ""
			}
			if cpuFlags.profileKernelOnly {
				params[types.ProfileKernelParam] = ""
			}

			cpuGadget := &ProfileGadget{
				gadgetName:    "profile",
				params:        params,
				commonFlags:   commonFlags,
				inProgressMsg: "Capturing stack traces",
				parser: &CPUParser{
					BaseParser: commonutils.NewBaseWidthParser[types.Report](columnsWidth, &commonFlags.OutputConfig),
					cpuFlags:   &cpuFlags,
				},
			}

			return cpuGadget.Run()
		},
	}

	cmd.PersistentFlags().BoolVarP(
		&cpuFlags.profileUserOnly,
		"user",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	cmd.PersistentFlags().BoolVarP(
		&cpuFlags.profileKernelOnly,
		"kernel",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func (p *CPUParser) DisplayResultsCallback(traceOutputMode string, results []string) error {
	// Print header
	switch p.OutputConfig.OutputMode {
	case commonutils.OutputModeJSON:
		// Nothing to print
	case commonutils.OutputModeColumns:
		fallthrough
	case commonutils.OutputModeCustomColumns:
		// Do not print the "stack" column header, it is not actually a column.
		var i int
		var col string

		// Remove it from the list of columns to be printed
		for i, col = range p.OutputConfig.CustomColumns {
			if col == "stack" {
				p.OutputConfig.CustomColumns = append(p.OutputConfig.CustomColumns[:i],
					p.OutputConfig.CustomColumns[i+1:]...)
				break
			}
		}

		fmt.Println(p.BuildColumnsHeader())

		// Add it back in the same position
		if col == "stack" {
			p.OutputConfig.CustomColumns = append(p.OutputConfig.CustomColumns[:i],
				append([]string{col}, p.OutputConfig.CustomColumns[i:]...)...)
		}
	}

	for _, r := range results {
		var reports []types.Report
		if err := json.Unmarshal([]byte(r), &reports); err != nil {
			return commonutils.WrapInErrUnmarshalOutput(err, r)
		}

		for _, report := range reports {
			fmt.Println(p.TransformReport(&report))
		}
	}

	return nil
}

// getReverseStringSlice return the reversed slice given as parameter.
func getReverseStringSlice(toReverse []string) string {
	if len(toReverse) == 0 {
		return ""
	}

	size := len(toReverse) - 1

	for i := 0; i < size/2; i++ {
		toReverse[i], toReverse[size-i] = toReverse[size-i], toReverse[i]
	}

	return fmt.Sprintf("\n\t%s", strings.Join(toReverse, "\n\t"))
}

func (p *CPUParser) TransformReport(report *types.Report) string {
	return p.Transform(report, func(e *types.Report) string {
		var sb strings.Builder

		for _, col := range p.OutputConfig.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], report.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], report.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], report.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], report.Container))
			case "pid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], report.Pid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], report.Comm))
			case "count":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], report.Count))
			case "stack":
				if p.cpuFlags.profileUserOnly {
					fmt.Fprint(&sb, getReverseStringSlice(report.UserStack))
				} else if p.cpuFlags.profileKernelOnly {
					fmt.Fprint(&sb, getReverseStringSlice(report.KernelStack))
				} else {
					fmt.Fprint(&sb, getReverseStringSlice(report.KernelStack), getReverseStringSlice(report.UserStack))
				}
			default:
				continue
			}

			// Needed when field is larger than the predefined columnsWidth.
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
