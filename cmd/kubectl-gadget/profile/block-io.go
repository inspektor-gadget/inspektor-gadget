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
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biolatency/types"
)

var biolatencyTraceConfig = &utils.TraceConfig{
	GadgetName:        "biolatency",
	TraceOutputMode:   "Status",
	TraceOutputState:  "Completed",
	TraceInitialState: "Started",
	CommonFlags:       &params,
}

var biolatencyCmd = &cobra.Command{
	Use:          "block-io",
	Short:        "Analyze block I/O performance through a latency distribution",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runBiolatency,
}

func init() {
	ProfilerCmd.AddCommand(biolatencyCmd)

	utils.AddCommonFlags(biolatencyCmd, &params)
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

func runBiolatency(cmd *cobra.Command, args []string) error {
	// Biolatency does not support filtering so we need to avoid adding
	// the default namespace configured in the kubeconfig file.
	if params.Namespace != "" && !params.NamespaceOverridden {
		params.Namespace = ""
	}

	if params.Node == "" {
		return utils.WrapInErrMissingArgs("--node")
	}

	biolatencyTraceConfig.Operation = "start"
	traceID, err := utils.CreateTrace(biolatencyTraceConfig)
	if err != nil {
		return utils.WrapInErrRunGadget(err)
	}

	defer utils.DeleteTrace(traceID)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	if params.Timeout != 0 {
		go func() {
			time.Sleep(time.Duration(params.Timeout) * time.Second)
			c <- os.Interrupt
		}()
	}

	if params.OutputMode != utils.OutputModeJSON {
		if params.Timeout != 0 {
			fmt.Printf("Tracing block device I/O...\n")
		} else {
			fmt.Printf("Tracing block device I/O... Hit Ctrl-C to end.")
		}
	}

	<-c

	if params.Timeout == 0 {
		// Trick to have ^C on the same line than above "Tracing block...", so the
		// gadget output begins on a "clean" line.
		fmt.Println()
	}
	err = utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return utils.WrapInErrStopGadget(err)
	}

	displayResultsCallback := func(results []gadgetv1alpha1.Trace) error {
		if len(results) != 1 {
			return errors.New("there should be only one result because biolatency runs on one node at a time")
		}

		var output string
		if params.OutputMode == utils.OutputModeJSON {
			output = results[0].Status.Output
		} else {
			var report types.Report
			if err := json.Unmarshal([]byte(results[0].Status.Output), &report); err != nil {
				return utils.WrapInErrUnmarshalOutput(err, results[0].Status.Output)
			}

			output = reportToString(report)
		}
		fmt.Printf("%s", output)

		return nil
	}

	err = utils.PrintTraceOutputFromStatus(traceID,
		biolatencyTraceConfig.TraceOutputState, displayResultsCallback)
	if err != nil {
		return utils.WrapInErrGetGadgetOutput(err)
	}

	return nil
}
