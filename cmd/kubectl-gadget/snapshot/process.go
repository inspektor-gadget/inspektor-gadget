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

type ProcessFlags struct {
	showThreads bool
}

func init() {
	processCmd := initProcessCmd()
	SnapshotCmd.AddCommand(processCmd)
}

func initProcessCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var processFlags ProcessFlags

	cmd := &cobra.Command{
		Use:   "process",
		Short: "Gather information about running processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &utils.TraceConfig{
				GadgetName:       "process-collector",
				Operation:        "collect",
				TraceOutputMode:  "Status",
				TraceOutputState: "Completed",
				CommonFlags:      &commonFlags,
			}

			callback := func(results []gadgetv1alpha1.Trace) error {
				allEvents := []types.Event{}

				for _, i := range results {
					if len(i.Status.Output) == 0 {
						continue
					}

					var events []types.Event
					if err := json.Unmarshal([]byte(i.Status.Output), &events); err != nil {
						return utils.WrapInErrUnmarshalOutput(err, i.Status.Output)
					}
					allEvents = append(allEvents, events...)
				}

				allEvents = sortProcessEvents(allEvents, &processFlags)

				switch commonFlags.OutputMode {
				case utils.OutputModeJSON:
					b, err := json.MarshalIndent(allEvents, "", "  ")
					if err != nil {
						return utils.WrapInErrMarshalOutput(err)
					}

					fmt.Printf("%s\n", b)
					return nil
				case utils.OutputModeColumns:
					fallthrough
				case utils.OutputModeCustomColumns:
					// In the snapshot gadgets it's possible to use a tabwriter because
					// we have the full list of events to print available, hence the
					// tablewriter is able to determine the columns width. In other
					// gadgets we don't know the size of all columns "a priori", hence
					// we have to do a best effort printing fixed-width columns.
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

					fmt.Fprintln(w, getProcessColsHeader(&processFlags, commonFlags.CustomColumns))
					for _, e := range allEvents {
						if e.Type != eventtypes.NORMAL {
							utils.ManageSpecialEvent(e.Event, commonFlags.Verbose)
							continue
						}

						fmt.Fprintln(w, transformProcessEvent(&e, &processFlags, &commonFlags.OutputConfig))
					}

					w.Flush()
				default:
					return utils.WrapInErrOutputModeNotSupported(commonFlags.OutputMode)
				}

				return nil
			}

			return utils.RunTraceAndPrintStatusOutput(config, callback)
		},
	}

	cmd.PersistentFlags().BoolVarP(
		&processFlags.showThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

// getProcessColsHeader returns a header with the default list of columns
// when it is not requested to use a subset of custom columns.
func getProcessColsHeader(processFlags *ProcessFlags, requestedCols []string) string {
	availableCols := map[string]struct{}{
		"node":      {},
		"namespace": {},
		"pod":       {},
		"container": {},
		"comm":      {},
		"tgid":      {},
		"pid":       {},
	}

	if len(requestedCols) == 0 {
		requestedCols = []string{"node", "namespace", "pod", "container", "comm", "pid"}
		if processFlags.showThreads {
			requestedCols = []string{"node", "namespace", "pod", "container", "comm", "tgid", "pid"}
		}
	}

	return buildSnapshotColsHeader(availableCols, requestedCols)
}

// transformProcessEvent is called to transform an event to columns
// format according to the parameters.
func transformProcessEvent(e *types.Event, processFlags *ProcessFlags, outputConf *utils.OutputConfig) string {
	var sb strings.Builder

	switch outputConf.OutputMode {
	case utils.OutputModeColumns:
		if processFlags.showThreads {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Tgid, e.Pid))
		} else {
			sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d",
				e.Node, e.Namespace, e.Pod, e.Container,
				e.Command, e.Pid))
		}
	case utils.OutputModeCustomColumns:
		for _, col := range outputConf.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%s", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%s", e.Container))
			case "comm":
				sb.WriteString(fmt.Sprintf("%s", e.Command))
			case "tgid":
				sb.WriteString(fmt.Sprintf("%d", e.Tgid))
			case "pid":
				sb.WriteString(fmt.Sprintf("%d", e.Pid))
			default:
				continue
			}
			sb.WriteRune('\t')
		}
	}

	return sb.String()
}

func sortProcessEvents(allProcesses []types.Event, processFlags *ProcessFlags) []types.Event {
	if !processFlags.showThreads {
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

	return allProcesses
}
