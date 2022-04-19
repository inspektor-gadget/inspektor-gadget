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
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
)

var (
	socketCollectorProtocol      string
	socketCollectorParamExtended bool
)

var socketCollectorCmd = &cobra.Command{
	Use:   "socket",
	Short: "Gather information about network sockets",
	RunE: func(cmd *cobra.Command, args []string) error {
		callback := func(results []gadgetv1alpha1.Trace) error {
			allSockets := []socketcollectortypes.Event{}

			for _, i := range results {
				var sockets []socketcollectortypes.Event
				json.Unmarshal([]byte(i.Status.Output), &sockets)
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
			case utils.OutputModeJSON:
				b, err := json.MarshalIndent(allSockets, "", "  ")
				if err != nil {
					return fmt.Errorf("error marshalling results: %w", err)
				}
				fmt.Printf("%s\n", b)
			case utils.OutputModeCustomColumns:
				table := utils.NewTableFormater(params.CustomColumns, map[string]int{})
				fmt.Println(table.GetHeader())
				transform := table.GetTransformFunc()

				for _, p := range allSockets {
					b, err := json.Marshal(p)
					if err != nil {
						return fmt.Errorf("error marshalling results: %w", err)
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
			return err
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

		return utils.RunTraceAndPrintStatusOutput(config, callback)
	},
}

func init() {
	SnapshotCmd.AddCommand(socketCollectorCmd)
	utils.AddCommonFlags(socketCollectorCmd, &params)

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
