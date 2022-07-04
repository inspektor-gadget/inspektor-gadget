// Copyright 2022 The Inspektor Gadget authors
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
	"fmt"
	"sort"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	"github.com/spf13/cobra"
)

const (
	SocketGadgetName = "socket-collector"
)

type SocketFlags struct {
	Protocol string
	Extended bool
}

type SocketParser struct {
	BaseSnapshotParser

	socketFlags *SocketFlags
}

func NewSocketCmd(
	socketFlags *SocketFlags,
	availableColumns map[string]struct{},
	outputConfig *utils.OutputConfig,
	customRun func(callback func(traceOutputMode string, results []string) error) error,
) *cobra.Command {
	socketGadget := &SnapshotGadget[types.Event]{
		outputConfig: outputConfig,
		parser: &SocketParser{
			BaseSnapshotParser: BaseSnapshotParser{
				AvailableColumns: availableColumns,
				OutputConfig:     outputConfig,
			},
			socketFlags: socketFlags,
		},
		customRun: customRun,
	}

	cmd := &cobra.Command{
		Use:   "socket",
		Short: "Gather information about TCP and UDP sockets",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if _, err := types.ParseProtocol(socketFlags.Protocol); err != nil {
				return err
			}

			if outputConfig.OutputMode == utils.OutputModeColumns && socketFlags.Extended {
				outputConfig.CustomColumns = append(outputConfig.CustomColumns, "inode")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return socketGadget.Run()
		},
	}

	var protocols []string
	for protocol := range types.ProtocolsMap {
		protocols = append(protocols, protocol)
	}

	cmd.PersistentFlags().StringVarP(
		&socketFlags.Protocol,
		"proto",
		"",
		"all",
		fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
	)
	cmd.PersistentFlags().BoolVarP(
		&socketFlags.Extended,
		"extend",
		"e",
		false,
		"Display other/more information (like socket inode)",
	)

	return cmd
}

func (s *SocketParser) TransformEvent(e *types.Event) string {
	var sb strings.Builder

	for _, col := range s.OutputConfig.CustomColumns {
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

	return sb.String()
}

func (s *SocketParser) SortEvents(allSockets *[]types.Event) {
	sort.Slice(*allSockets, func(i, j int) bool {
		si, sj := (*allSockets)[i], (*allSockets)[j]
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
