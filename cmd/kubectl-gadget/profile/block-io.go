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
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biolatency/types"
)

type BlockIOParser struct {
	outputConfig *utils.OutputConfig
}

func newBlockIOCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	cmd := &cobra.Command{
		Use:          "block-io",
		Short:        "Analyze block I/O performance through a latency distribution",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Biolatency does not support filtering so we need to avoid adding
			// the default namespace configured in the kubeconfig file.
			if commonFlags.Namespace != "" && !commonFlags.NamespaceOverridden {
				commonFlags.Namespace = ""
			}

			if commonFlags.Node == "" {
				return utils.WrapInErrMissingArgs("--node")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			blockIOGadget := &ProfileGadget{
				gadgetName:    "biolatency",
				commonFlags:   &commonFlags,
				inProgressMsg: "Tracing block device I/O",
				parser: &BlockIOParser{
					outputConfig: &commonFlags.OutputConfig,
				},
			}

			return blockIOGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

// starsToString prints a line of the histogram.
// It is a golang translation of iovisor/bcc print_stars():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L878-L893
func starsToString(val, valMax, width uint64) string {
	minVal := uint64(0)
	if val < valMax {
		minVal = val
	} else {
		minVal = valMax
	}

	stars := minVal * width / valMax
	spaces := width - stars

	var sb strings.Builder
	sb.WriteString(strings.Repeat("*", int(stars)))
	sb.WriteString(strings.Repeat(" ", int(spaces)))
	if val > valMax {
		sb.WriteByte('+')
	}

	return sb.String()
}

// reportToString prints an histogram from a types.Report.
// It is a golang adaption of iovisor/bcc print_log2_hist():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L895-L932
func reportToString(report types.Report) string {
	if len(report.Data) == 0 {
		return ""
	}

	valMax := uint64(0)
	for _, data := range report.Data {
		if data.Count > valMax {
			valMax = data.Count
		}
	}

	// reportEntries maximum value is C.MAX_SLOTS which is 27, so we take the
	// value when idx_max <= 32.
	spaceBefore := 5
	spaceAfter := 19
	width := 10
	stars := 40

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%*s%-*s : count    distribution\n", spaceBefore,
		"", spaceAfter, report.ValType))

	for _, data := range report.Data {
		sb.WriteString(fmt.Sprintf("%*d -> %-*d : %-8d |%s|\n", width,
			data.IntervalStart, width, data.IntervalEnd, data.Count,
			starsToString(data.Count, valMax, uint64(stars))))
	}

	return sb.String()
}

func (p *BlockIOParser) DisplayResultsCallback(traceOutputMode string, results []string) error {
	l := len(results)
	if l > 1 {
		return errors.New("there should be only one result because biolatency runs on one node at a time")
	} else if l == 0 {
		// Nothing to print, errors/warnings were already printed
		return nil
	}

	var output string
	if p.outputConfig.OutputMode == utils.OutputModeJSON {
		output = results[0] + "\n"
	} else {
		var report types.Report
		if err := json.Unmarshal([]byte(results[0]), &report); err != nil {
			return utils.WrapInErrUnmarshalOutput(err, results[0])
		}

		output = reportToString(report)
	}

	fmt.Printf("%s", output)

	return nil
}
