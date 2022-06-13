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
	"os/signal"
	"strings"
	"time"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/types"

	"github.com/spf13/cobra"
)

var (
	profileKernel bool
	profileUser   bool
)

var cpuTraceConfig = &utils.TraceConfig{
	GadgetName:        "profile",
	TraceOutputMode:   "Status",
	TraceOutputState:  "Completed",
	TraceInitialState: "Started",
	CommonFlags:       &params,
}

var profileCmd = &cobra.Command{
	Use:          "cpu",
	Short:        "Analyze CPU performance by sampling stack traces",
	RunE:         runProfileCPU,
	SilenceUsage: true,
}

func init() {
	ProfilerCmd.AddCommand(profileCmd)
	utils.AddCommonFlags(profileCmd, &params)

	profileCmd.PersistentFlags().BoolVarP(
		&profileUser,
		"user",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	profileCmd.PersistentFlags().BoolVarP(
		&profileKernel,
		"kernel",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)
}

// reverseStringSlice reverse the slice of strings given as parameter.
func reverseStringSlice(strings []string) {
	size := len(strings) - 1

	for i := 0; i < size/2; i++ {
		strings[i], strings[size-i] = strings[size-i], strings[i]
	}
}

func getCustomProfileColsHeader(cols []string) string {
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
		case "count":
			sb.WriteString(fmt.Sprintf("%-6s", "COUNT"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func runProfileCPU(cmd *cobra.Command, args []string) error {
	if profileUser && profileKernel {
		return utils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
	}

	cpuTraceConfig.Parameters = map[string]string{}

	if profileUser {
		cpuTraceConfig.Parameters[types.ProfileUserParam] = ""
	}

	if profileKernel {
		cpuTraceConfig.Parameters[types.ProfileKernelParam] = ""
	}

	cpuTraceConfig.Operation = "start"
	traceID, err := utils.CreateTrace(cpuTraceConfig)
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
			fmt.Printf("Capturing stack traces...")
		} else {
			fmt.Printf("Capturing stack traces... Hit Ctrl-C to end.")
		}
	}

	<-c

	fmt.Println()
	err = utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return utils.WrapInErrStopGadget(err)
	}

	displayResultsCallback := func(traces []gadgetv1alpha1.Trace) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomProfileColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-16s %-6s %-6s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER", "COMM", "PID", "COUNT")
		}

		for _, trace := range traces {
			var reports []types.Report
			if err := json.Unmarshal([]byte(trace.Status.Output), &reports); err != nil {
				return utils.WrapInErrUnmarshalOutput(err, trace.Status.Output)
			}

			for _, report := range reports {
				switch params.OutputMode {
				case utils.OutputModeColumns:
					var sb strings.Builder

					fmt.Fprintf(&sb, "%-16s %-16s %-16s %-16s %-16s %-7d %-6d\n",
						report.Node, report.Namespace, report.Pod, report.Container,
						report.Comm, report.Pid, report.Count)

					if profileUser {
						reverseStringSlice(report.UserStack)

						fmt.Fprintf(&sb, "\t%s", strings.Join(report.UserStack, "\n\t"))
					} else if profileKernel {
						reverseStringSlice(report.KernelStack)

						fmt.Fprintf(&sb, "\t%s", strings.Join(report.KernelStack, "\n\t"))
					} else {
						reverseStringSlice(report.KernelStack)
						reverseStringSlice(report.UserStack)

						fmt.Fprintf(&sb, "\t%s\n\t%s", strings.Join(report.KernelStack, "\n\t"), strings.Join(report.UserStack, "\n\t"))
					}

					fmt.Println(sb.String())
				case utils.OutputModeJSON:
					b, err := json.Marshal(report)
					if err != nil {
						return utils.WrapInErrMarshalOutput(err)
					}
					fmt.Println(string(b))
				case utils.OutputModeCustomColumns:
					var sb strings.Builder

					for _, col := range params.CustomColumns {
						switch col {
						case "node":
							sb.WriteString(fmt.Sprintf("%-16s", report.Node))
						case "namespace":
							sb.WriteString(fmt.Sprintf("%-16s", report.Namespace))
						case "pod":
							sb.WriteString(fmt.Sprintf("%-16s", report.Pod))
						case "container":
							sb.WriteString(fmt.Sprintf("%-16s", report.Container))
						case "comm":
							sb.WriteString(fmt.Sprintf("%-16s", report.Comm))
						case "pid":
							sb.WriteString(fmt.Sprintf("%-6d", report.Pid))
						case "count":
							sb.WriteString(fmt.Sprintf("%-6d", report.Count))
						case "stack":
							reverseStringSlice(report.KernelStack)
							reverseStringSlice(report.UserStack)

							fmt.Fprintf(&sb, "\n\t%s\n\t%s", strings.Join(report.KernelStack, "\n\t"), strings.Join(report.UserStack, "\n\t"))
						}
						sb.WriteRune(' ')
					}

					fmt.Println(sb.String())
				}
			}
		}

		return nil
	}

	err = utils.PrintTraceOutputFromStatus(traceID,
		cpuTraceConfig.TraceOutputState, displayResultsCallback)
	if err != nil {
		return utils.WrapInErrGetGadgetOutput(err)
	}

	return nil
}
