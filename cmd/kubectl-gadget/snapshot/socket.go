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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

var (
	socketCollectorProtocol      string
	socketCollectorParamExtended bool
)

var socketCollectorCmd = &cobra.Command{
	Use:   "socket",
	Short: "Gather information about TCP and UDP sockets",
	RunE: func(cmd *cobra.Command, args []string) error {
		callback := func(results []gadgetv1alpha1.Trace) error {
			allSockets := []types.Event{}

			for _, i := range results {
				if len(i.Status.Output) == 0 {
					continue
				}

				var sockets []types.Event
				if err := json.Unmarshal([]byte(i.Status.Output), &sockets); err != nil {
					return utils.WrapInErrUnmarshalOutput(err, i.Status.Output)
				}

				allSockets = append(allSockets, sockets...)
			}

			return printSockets(allSockets)
		}

		if _, err := types.ParseProtocol(socketCollectorProtocol); err != nil {
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
	for protocol := range types.ProtocolsMap {
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

func getCustomSocketColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString("NODE\t")
		case "namespace":
			sb.WriteString("NAMESPACE\t")
		case "pod":
			sb.WriteString("POD\t")
		case "protocol":
			sb.WriteString("PROTOCOL\t")
		case "local":
			sb.WriteString("LOCAL\t")
		case "remote":
			sb.WriteString("REMOTE\t")
		case "status":
			sb.WriteString("STATUS\t")
		case "inode":
			sb.WriteString("INODE\t")
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

// socketTransformEvent is called to transform an event to columns
// format according to the parameters
func socketTransformEvent(e types.Event) string {
	var sb strings.Builder

	if e.Type != eventtypes.NORMAL {
		utils.ManageSpecialEvent(e.Event, params.Verbose)
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		extendedInformation := ""
		if socketCollectorParamExtended {
			extendedInformation = fmt.Sprintf("\t%d", e.InodeNumber)
		}

		sb.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s:%d\t%s:%d\t%s%s",
			e.Node, e.Namespace, e.Pod, e.Protocol,
			e.LocalAddress, e.LocalPort, e.RemoteAddress, e.RemotePort,
			e.Status, extendedInformation))
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%s\t", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%s\t", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%s\t", e.Pod))
			case "protocol":
				sb.WriteString(fmt.Sprintf("%s\t", e.Protocol))
			case "local":
				sb.WriteString(fmt.Sprintf("%s:%d\t", e.LocalAddress, e.LocalPort))
			case "remote":
				sb.WriteString(fmt.Sprintf("%s:%d\t", e.RemoteAddress, e.RemotePort))
			case "status":
				sb.WriteString(fmt.Sprintf("%s\t", e.Status))
			case "inode":
				sb.WriteString(fmt.Sprintf("%d\t", e.InodeNumber))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func printSockets(allSockets []types.Event) error {
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

	// JSON output mode does not need any additional parsing
	if params.OutputMode == utils.OutputModeJSON {
		b, err := json.MarshalIndent(allSockets, "", "  ")
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
		fmt.Fprintln(w, getCustomSocketColsHeader(params.CustomColumns))
	case utils.OutputModeColumns:
		extendedHeader := ""
		if socketCollectorParamExtended {
			extendedHeader = "\tINODE"
		}
		fmt.Fprintf(w, "NODE\tNAMESPACE\tPOD\tPROTOCOL\tLOCAL\tREMOTE\tSTATUS%s\n", extendedHeader)
	}

	for _, s := range allSockets {
		fmt.Fprintln(w, socketTransformEvent(s))
	}

	w.Flush()

	return nil
}
