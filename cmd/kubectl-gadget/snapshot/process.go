// Copyright 2019-2021 The Inspektor Gadget authors
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

package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

var processCollectorParamThreads bool

var processCollectorCmd = &cobra.Command{
	Use:   "process",
	Short: "Gather information about running processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		callback := func(results []gadgetv1alpha1.Trace) error {
			allProcesses := []types.Event{}

			for _, i := range results {
				if len(i.Status.Output) == 0 {
					continue
				}

				var processes []types.Event
				if err := json.Unmarshal([]byte(i.Status.Output), &processes); err != nil {
					return utils.WrapInErrUnmarshalOutput(err, i.Status.Output)
				}

				allProcesses = append(allProcesses, processes...)
			}

			return printProcesses(allProcesses)
		}

		config := &utils.TraceConfig{
			GadgetName:       "process-collector",
			Operation:        "collect",
			TraceOutputMode:  "Status",
			TraceOutputState: "Completed",
			CommonFlags:      &params,
		}

		return utils.RunTraceAndPrintStatusOutput(config, callback)
	},
}

func init() {
	SnapshotCmd.AddCommand(processCollectorCmd)
	utils.AddCommonFlags(processCollectorCmd, &params)

	processCollectorCmd.PersistentFlags().BoolVarP(
		&processCollectorParamThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)
}

func getCustomProcessColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString("NODE\t")
		case "namespace":
			sb.WriteString("NAMESPACE\t")
		case "pod":
			sb.WriteString("POD\t")
		case "container":
			sb.WriteString("CONTAINER\t")
		case "comm":
			sb.WriteString("COMM\t")
		case "tgid":
			sb.WriteString("TGID\t")
		case "pid":
			sb.WriteString("PID\t")
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

// processTransformEvent is called to transform an event to columns
// format according to the parameters
func processTransformEvent(e types.Event) string {
	var sb strings.Builder

	if e.Type != eventtypes.NORMAL {
		utils.ManageSpecialEvent(e.Event, params.Verbose)
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		if processCollectorParamThreads {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Tgid, e.Pid))
		} else {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Pid))
		}
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%s\t", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%s\t", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%s\t", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%s\t", e.Container))
			case "comm":
				sb.WriteString(fmt.Sprintf("%s\t", e.Command))
			case "tgid":
				sb.WriteString(fmt.Sprintf("%d\t", e.Tgid))
			case "pid":
				sb.WriteString(fmt.Sprintf("%d\t", e.Pid))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func printProcesses(allProcesses []types.Event) error {
	if !processCollectorParamThreads {
		allProcessesTrimmed := []types.Event{}
		for _, i := range allProcesses {
			if i.Tgid == i.Pid {
				allProcessesTrimmed = append(allProcessesTrimmed, i)
			}
		}
		allProcesses = allProcessesTrimmed
	}

	sort.Slice(allProcesses, func(i, j int) bool {
		pi, pj := allProcesses[i], allProcesses[j]
		switch {
		case pi.Node != pj.Node:
			return pi.Node < pj.Node
		case pi.Namespace != pj.Namespace:
			return pi.Namespace < pj.Namespace
		case pi.Pod != pj.Pod:
			return pi.Pod < pj.Pod
		case pi.Container != pj.Container:
			return pi.Container < pj.Container
		case pi.Command != pj.Command:
			return pi.Command < pj.Command
		case pi.Tgid != pj.Tgid:
			return pi.Tgid < pj.Tgid
		default:
			return pi.Pid < pj.Pid
		}
	})

	// JSON output mode does not need any additional parsing
	if params.OutputMode == utils.OutputModeJSON {
		b, err := json.MarshalIndent(allProcesses, "", "  ")
		if err != nil {
			return utils.WrapInErrMarshalOutput(err)
		}
		fmt.Printf("%s\n", b)
		return nil
	}

	// In the snapshot gadgets it's possible to use a tabwriter because we have
	// the full list of events to print available, hence the tablewriter is able
	// to determine the columns width. In other gadgets we don't know the size
	// of all columns "a priori", hence we have to do a best effort printing
	// fixed-width columns.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	// Print all or requested columns
	switch params.OutputMode {
	case utils.OutputModeCustomColumns:
		fmt.Fprintln(w, getCustomProcessColsHeader(params.CustomColumns))
	case utils.OutputModeColumns:
		if processCollectorParamThreads {
			fmt.Fprintln(w, "NODE\tNAMESPACE\tPOD\tCONTAINER\tCOMM\tTGID\tPID")
		} else {
			fmt.Fprintln(w, "NODE\tNAMESPACE\tPOD\tCONTAINER\tCOMM\tPID")
		}
	}

	for _, p := range allProcesses {
		fmt.Fprintln(w, processTransformEvent(p))
	}

	w.Flush()

	return nil
}
