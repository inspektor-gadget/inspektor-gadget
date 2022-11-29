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

package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	cpuTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

type CPUFlags struct {
	ProfileKernelOnly bool
	ProfileUserOnly   bool
}

type CPUParser struct {
	utils.GadgetParser[cpuTypes.Report]
	utils.OutputConfig
	CPUFlags *CPUFlags
}

func NewCPUCmd(runCmd func(*cobra.Command, []string) error, flags *CPUFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "cpu",
		Short:        "Analyze CPU performance by sampling stack traces",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         runCmd,
	}

	cmd.PersistentFlags().BoolVarP(
		&flags.ProfileUserOnly,
		"user-stack",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	cmd.PersistentFlags().BoolVarP(
		&flags.ProfileKernelOnly,
		"kernel-stack",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)

	return cmd
}

func (p *CPUParser) DisplayResultsCallback(traceOutputMode string, results []string) error {
	if p.OutputConfig.OutputMode != utils.OutputModeJSON {
		fmt.Println(p.BuildColumnsHeader())
	}

	for _, r := range results {
		var reports []cpuTypes.Report
		if err := json.Unmarshal([]byte(r), &reports); err != nil {
			return utils.WrapInErrUnmarshalOutput(err, r)
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

func (p *CPUParser) TransformReport(report *cpuTypes.Report) string {
	switch p.OutputConfig.OutputMode {
	case utils.OutputModeJSON:
		b, err := json.Marshal(report)
		if err != nil {
			fmt.Fprint(os.Stderr, fmt.Sprint(utils.WrapInErrMarshalOutput(err)))
			return ""
		}

		return string(b)
	case utils.OutputModeColumns:
		fallthrough
	case utils.OutputModeCustomColumns:
		otherCols := p.TransformIntoColumns(report)
		if p.CPUFlags.ProfileUserOnly {
			return otherCols + getReverseStringSlice(report.UserStack)
		} else if p.CPUFlags.ProfileKernelOnly {
			return otherCols + getReverseStringSlice(report.KernelStack)
		} else {
			return otherCols + getReverseStringSlice(report.KernelStack) + getReverseStringSlice(report.UserStack)
		}
	}
	return ""
}
