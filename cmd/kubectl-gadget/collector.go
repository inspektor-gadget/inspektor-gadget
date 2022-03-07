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

package main

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
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
)

var processCollectorCmd = &cobra.Command{
	Use:   "process-collector",
	Short: "Gather information about running processes",
	RunE:  processCollectorCmdRun,
}

var socketCollectorCmd = &cobra.Command{
	Use:   "socket-collector",
	Short: "Gather information about network sockets",
	RunE:  socketCollectorCmdRun,
}

var (
	processCollectorParamThreads bool
	socketCollectorProtocol      string
	socketCollectorParamExtended bool
)

func init() {
	commands := []*cobra.Command{
		processCollectorCmd,
		socketCollectorCmd,
	}

	// Add common flags for all collector gadgets
	for _, command := range commands {
		rootCmd.AddCommand(command)
		utils.AddCommonFlags(command, &params)
	}

	// Add specific flags
	processCollectorCmd.PersistentFlags().BoolVarP(
		&processCollectorParamThreads,
		"threads",
		"t",
		false,
		"Show all threads",
	)

	var protocols []string
	for protocol := range socketcollectortypes.ProtocolsMap {
		protocols = append(protocols, protocol)
	}

	socketCollectorCmd.PersistentFlags().StringVarP(
		&socketCollectorProtocol,
		"proto",
		"",
		"all",
		fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
	)
	socketCollectorCmd.PersistentFlags().BoolVarP(
		&socketCollectorParamExtended,
		"extend",
		"e",
		false,
		"Display other/more information (like socket inode)",
	)
}

func processCollectorCmdRun(cmd *cobra.Command, args []string) error {
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
			if err := json.Unmarshal([]byte(i.Status.Output), &processes); err != nil {
				return utils.WrapInErrUnmarshalOutput(err)
			}
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
		case utils.OutputModeJson:
			b, err := json.MarshalIndent(allProcesses, "", "  ")
			if err != nil {
				return utils.WrapInErrMarshalOutput(err)
			}
			fmt.Printf("%s\n", b)
		case utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, map[string]int{})
			fmt.Println(table.GetHeader())
			transform := table.GetTransformFunc()

			for _, p := range allProcesses {
				b, err := json.Marshal(p)
				if err != nil {
					return utils.WrapInErrMarshalOutput(err)
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

	err := utils.RunTraceAndPrintStatusOutput(config, callback)
	if err != nil {
		return utils.WrapInErrRunGadget(err)
	}

	return nil
}

func socketCollectorCmdRun(cmd *cobra.Command, args []string) error {
	callback := func(results []gadgetv1alpha1.Trace) error {
		allSockets := []socketcollectortypes.Event{}

		for _, i := range results {
			var sockets []socketcollectortypes.Event
			if err := json.Unmarshal([]byte(i.Status.Output), &sockets); err != nil {
				return utils.WrapInErrUnmarshalOutput(err)
			}
			allSockets = append(allSockets, sockets...)
		}

		sort.Slice(allSockets, func(i, j int) bool {
			si, sj := allSockets[i], allSockets[j]
			switch {
			case si.Event.Node != sj.Event.Node:
				return si.Event.Node < sj.Event.Node
			case si.Event.Namespace != sj.Event.Namespace:
				return si.Event.Namespace < sj.Event.Namespace
			case si.Event.Pod != sj.Event.Pod:
				return si.Event.Pod < sj.Event.Pod
			case si.Protocol != sj.Protocol:
				return si.Protocol < sj.Protocol
			case si.Status != sj.Status:
				return si.Status < sj.Status
			case si.LocalAddress != sj.LocalAddress:
				return si.LocalAddress < sj.LocalAddress
			case si.RemoteAddress != sj.RemoteAddress:
				return si.RemoteAddress < sj.RemoteAddress
			case si.LocalPort != sj.LocalPort:
				return si.LocalPort < sj.LocalPort
			case si.RemotePort != sj.RemotePort:
				return si.RemotePort < sj.RemotePort
			default:
				return si.InodeNumber < sj.InodeNumber
			}
		})

		switch params.OutputMode {
		case utils.OutputModeJson:
			b, err := json.MarshalIndent(allSockets, "", "  ")
			if err != nil {
				return utils.WrapInErrMarshalOutput(err)
			}
			fmt.Printf("%s\n", b)
		case utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, map[string]int{})
			fmt.Println(table.GetHeader())
			transform := table.GetTransformFunc()

			for _, p := range allSockets {
				b, err := json.Marshal(p)
				if err != nil {
					return utils.WrapInErrMarshalOutput(err)
				}

				fmt.Println(transform(string(b)))
			}
		default:
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

			extendedHeader := "\n"
			if socketCollectorParamExtended {
				extendedHeader = "\tINODE\n"
			}

			fmt.Fprintf(w, "NODE\tNAMESPACE\tPOD\tPROTOCOL\tLOCAL\tREMOTE\tSTATUS%s", extendedHeader)

			for _, s := range allSockets {
				extendedInformation := "\n"
				if socketCollectorParamExtended {
					extendedInformation = fmt.Sprintf("\t%d\n", s.InodeNumber)
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s:%d\t%s:%d\t%s%s",
					s.Event.Node,
					s.Event.Namespace,
					s.Event.Pod,
					s.Protocol,
					s.LocalAddress,
					s.LocalPort,
					s.RemoteAddress,
					s.RemotePort,
					s.Status,
					extendedInformation,
				)
			}
			w.Flush()
		}

		return nil
	}

	if _, err := socketcollectortypes.ParseProtocol(socketCollectorProtocol); err != nil {
		return utils.WrapInErrInvalidArg("--proto", err)
	}

	config := &utils.TraceConfig{
		GadgetName:       "socket-collector",
		Operation:        "collect",
		TraceOutputMode:  "Status",
		TraceOutputState: "Completed",
		CommonFlags:      &params,
		Parameters: map[string]string{
			"protocol": socketCollectorProtocol,
		},
	}

	err := utils.RunTraceAndPrintStatusOutput(config, callback)
	if err != nil {
		return utils.WrapInErrRunGadget(err)
	}

	return nil
}
