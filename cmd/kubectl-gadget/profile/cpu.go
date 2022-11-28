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
	"os"
	"strings"

	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
)

type CPUParser struct {
	commonutils.GadgetParser[types.Report]
	commonutils.OutputConfig
	cpuFlags *commonprofile.CPUFlags
}

func newCPUCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var cpuFlags commonprofile.CPUFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		if cpuFlags.ProfileUserOnly && cpuFlags.ProfileKernelOnly {
			return commonutils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
		}

		parser, err := commonutils.NewGadgetParserWithK8sInfo(&commonFlags.OutputConfig, types.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		params := map[string]string{}
		if cpuFlags.ProfileUserOnly {
			params[types.ProfileUserParam] = ""
		}
		if cpuFlags.ProfileKernelOnly {
			params[types.ProfileKernelParam] = ""
		}

		cpuGadget := &ProfileGadget{
			gadgetName:    "profile",
			params:        params,
			commonFlags:   &commonFlags,
			inProgressMsg: "Capturing stack traces",
			parser: &CPUParser{
				GadgetParser: *parser,
				OutputConfig: commonFlags.OutputConfig,
				cpuFlags:     &cpuFlags,
			},
		}

		return cpuGadget.Run()
	}

	cmd := commonprofile.NewCPUCmd(runCmd, &cpuFlags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

func (p *CPUParser) DisplayResultsCallback(traceOutputMode string, results []string) error {
	if p.OutputConfig.OutputMode != commonutils.OutputModeJSON {
		fmt.Println(p.BuildColumnsHeader())
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
	switch p.OutputConfig.OutputMode {
	case commonutils.OutputModeJSON:
		b, err := json.Marshal(report)
		if err != nil {
			fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
			return ""
		}

		return string(b)
	case commonutils.OutputModeColumns:
		fallthrough
	case commonutils.OutputModeCustomColumns:
		otherCols := p.TransformIntoColumns(report)
		if p.cpuFlags.ProfileUserOnly {
			return otherCols + getReverseStringSlice(report.UserStack)
		} else if p.cpuFlags.ProfileKernelOnly {
			return otherCols + getReverseStringSlice(report.KernelStack)
		} else {
			return otherCols + getReverseStringSlice(report.KernelStack) + getReverseStringSlice(report.UserStack)
		}
	}
	return ""
}
