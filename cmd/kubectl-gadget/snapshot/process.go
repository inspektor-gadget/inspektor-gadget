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
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

var processCollectorParamThreads bool

var processCollectorCmd = &cobra.Command{
	Use:   "process",
	Short: "Gather information about running processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		callback := func(results []gadgetv1alpha1.Trace) error {
			// Display results
			type Process struct {
				Tgid                int    `json:"tgid,omitempty"`
				Pid                 int    `json:"pid,omitempty"`
				Comm                string `json:"comm,omitempty"`
				KubernetesNamespace string `json:"namespace,omitempty"`
				KubernetesPod       string `json:"pod,omitempty"`
				KubernetesContainer string `json:"container,omitempty"`
				KubernetesNode      string `json:"node,omitempty"`
			}
			allProcesses := []Process{}

			for _, i := range results {
				processes := []Process{}
				json.Unmarshal([]byte(i.Status.Output), &processes)
				allProcesses = append(allProcesses, processes...)
			}
			if !processCollectorParamThreads {
				allProcessesTrimmed := []Process{}
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
				case pi.KubernetesNode != pj.KubernetesNode:
					return pi.KubernetesNode < pj.KubernetesNode
				case pi.KubernetesNamespace != pj.KubernetesNamespace:
					return pi.KubernetesNamespace < pj.KubernetesNamespace
				case pi.KubernetesPod != pj.KubernetesPod:
					return pi.KubernetesPod < pj.KubernetesPod
				case pi.KubernetesContainer != pj.KubernetesContainer:
					return pi.KubernetesContainer < pj.KubernetesContainer
				case pi.Comm != pj.Comm:
					return pi.Comm < pj.Comm
				case pi.Tgid != pj.Tgid:
					return pi.Tgid < pj.Tgid
				default:
					return pi.Pid < pj.Pid

				}
			})

			switch params.OutputMode {
			case utils.OutputModeJSON:
				b, err := json.MarshalIndent(allProcesses, "", "  ")
				if err != nil {
					return fmt.Errorf("error marshalling results: %w", err)
				}
				fmt.Printf("%s\n", b)
			case utils.OutputModeCustomColumns:
				table := utils.NewTableFormater(params.CustomColumns, map[string]int{})
				fmt.Println(table.GetHeader())
				transform := table.GetTransformFunc()

				for _, p := range allProcesses {
					b, err := json.Marshal(p)
					if err != nil {
						return fmt.Errorf("error marshalling results: %w", err)
					}

					fmt.Println(transform(string(b)))
				}
			default:
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
				if processCollectorParamThreads {
					fmt.Fprintln(w, "NODE\tNAMESPACE\tPOD\tCONTAINER\tCOMM\tTGID\tPID\t")
					for _, p := range allProcesses {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t\n",
							p.KubernetesNode,
							p.KubernetesNamespace,
							p.KubernetesPod,
							p.KubernetesContainer,
							p.Comm,
							p.Tgid,
							p.Pid,
						)
					}
				} else {
					fmt.Fprintln(w, "NODE\tNAMESPACE\tPOD\tCONTAINER\tCOMM\tPID\t")
					for _, p := range allProcesses {
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t\n",
							p.KubernetesNode,
							p.KubernetesNamespace,
							p.KubernetesPod,
							p.KubernetesContainer,
							p.Comm,
							p.Pid,
						)
					}
				}
				w.Flush()
			}

			return nil
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
