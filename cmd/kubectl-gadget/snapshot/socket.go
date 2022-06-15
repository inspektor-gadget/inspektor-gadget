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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type SocketFlags struct {
	protocol string
	extended bool
}

func init() {
	socketCmd := initSocketCmd()
	SnapshotCmd.AddCommand(socketCmd)
}

func initSocketCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var socketFlags SocketFlags

	cmd := &cobra.Command{
		Use:   "socket",
		Short: "Gather information about TCP and UDP sockets",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if _, err := types.ParseProtocol(socketFlags.protocol); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			config := &utils.TraceConfig{
				GadgetName:       "socket-collector",
				Operation:        "collect",
				TraceOutputMode:  "Status",
				TraceOutputState: "Completed",
				CommonFlags:      &commonFlags,
				Parameters: map[string]string{
					"protocol": socketFlags.protocol,
				},
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

				sortSocketEvents(allEvents)

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

					fmt.Fprintln(w, getSocketColsHeader(&socketFlags, commonFlags.CustomColumns))

					for _, e := range allEvents {
						if e.Type != eventtypes.NORMAL {
							utils.ManageSpecialEvent(e.Event, commonFlags.Verbose)
							continue
						}

						fmt.Fprintln(w, transformSocketEvent(&e, &socketFlags, &commonFlags.OutputConfig))
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

	var protocols []string
	for protocol := range types.ProtocolsMap {
		protocols = append(protocols, protocol)
	}

	cmd.PersistentFlags().StringVarP(
		&socketFlags.protocol,
		"proto",
		"",
		"all",
		fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
	)
	cmd.PersistentFlags().BoolVarP(
		&socketFlags.extended,
		"extend",
		"e",
		false,
		"Display other/more information (like socket inode)",
	)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}

// getSocketColsHeader returns a header with the default list of columns
// when it is not requested to use a subset of custom columns.
func getSocketColsHeader(socketFlags *SocketFlags, requestedCols []string) string {
	availableCols := map[string]struct{}{
		"node":      {},
		"namespace": {},
		"pod":       {},
		"protocol":  {},
		"local":     {},
		"remote":    {},
		"status":    {},
		"inode":     {},
	}

	if len(requestedCols) == 0 {
		requestedCols = []string{"node", "namespace", "pod", "protocol", "local", "remote", "status"}
		if socketFlags.extended {
			requestedCols = append(requestedCols, "inode")
		}
	}

	return buildSnapshotColsHeader(availableCols, requestedCols)
}

// transformSocketEvent is called to transform an event to columns
// format according to the parameters.
func transformSocketEvent(e *types.Event, socketFlags *SocketFlags, outputConf *utils.OutputConfig) string {
	var sb strings.Builder

	switch outputConf.OutputMode {
	case utils.OutputModeColumns:
		extendedInformation := ""
		if socketFlags.extended {
			extendedInformation = fmt.Sprintf("\t%d", e.InodeNumber)
		}

		sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s:%d\t%s:%d\t%s%s",
			e.Node, e.Namespace, e.Pod, e.Protocol,
			e.LocalAddress, e.LocalPort, e.RemoteAddress, e.RemotePort,
			e.Status, extendedInformation))
	case utils.OutputModeCustomColumns:
		for _, col := range outputConf.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%s", e.Pod))
			case "protocol":
				sb.WriteString(fmt.Sprintf("%s", e.Protocol))
			case "local":
				sb.WriteString(fmt.Sprintf("%s:%d", e.LocalAddress, e.LocalPort))
			case "remote":
				sb.WriteString(fmt.Sprintf("%s:%d", e.RemoteAddress, e.RemotePort))
			case "status":
				sb.WriteString(fmt.Sprintf("%s", e.Status))
			case "inode":
				sb.WriteString(fmt.Sprintf("%d", e.InodeNumber))
			default:
				continue
			}
			sb.WriteRune('\t')
		}
	}

	return sb.String()
}

func sortSocketEvents(allSockets []types.Event) {
	sort.Slice(allSockets, func(i, j int) bool {
		si, sj := allSockets[i], allSockets[j]
		switch {
		case si.Node != sj.Node:
			return si.Node < sj.Node
		case si.Namespace != sj.Namespace:
			return si.Namespace < sj.Namespace
		case si.Pod != sj.Pod:
			return si.Pod < sj.Pod
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
}
