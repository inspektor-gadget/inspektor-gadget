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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/spf13/cobra"
)

type SocketFlags struct {
	Extended bool
	Protocol string

	ParsedProtocol types.Proto
}

type SocketParser struct {
	commonutils.BaseParser[types.Event]
}

func newSocketParser(outputConfig *commonutils.OutputConfig, flags *SocketFlags, prependColumns []string) SnapshotParser[types.Event] {
	availableColumns := []string{
		// TODO: Move Kubernetes metadata columns to common/utils.
		"node",
		"namespace",
		"pod",
		"protocol",
		"local",
		"remote",
		"status",
		"inode",
	}

	if len(outputConfig.CustomColumns) == 0 {
		outputConfig.CustomColumns = GetSocketDefaultColumns()
		if len(prependColumns) != 0 {
			outputConfig.CustomColumns = append(prependColumns, outputConfig.CustomColumns...)
		}
	}

	if outputConfig.OutputMode == commonutils.OutputModeColumns && flags.Extended {
		outputConfig.CustomColumns = append(outputConfig.CustomColumns, "inode")
	}

	return &SocketParser{
		BaseParser: commonutils.NewBaseTabParser[types.Event](availableColumns, outputConfig),
	}
}

func NewSocketParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *SocketFlags) SnapshotParser[types.Event] {
	return newSocketParser(outputConfig, flags, commonutils.GetKubernetesColumns())
}

func NewSocketParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *SocketFlags) SnapshotParser[types.Event] {
	return newSocketParser(outputConfig, flags, commonutils.GetContainerRuntimeColumns())
}

func NewSocketParser(outputConfig *commonutils.OutputConfig, flags *SocketFlags) SnapshotParser[types.Event] {
	return newSocketParser(outputConfig, flags, nil)
}

func (s *SocketParser) TransformToColumns(e *types.Event) string {
	var sb strings.Builder

	for _, col := range s.OutputConfig.CustomColumns {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesNode))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesNamespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%s", e.KubernetesPodName))
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
		case si.KubernetesNode != sj.KubernetesNode:
			return si.KubernetesNode < sj.KubernetesNode
		case si.KubernetesNamespace != sj.KubernetesNamespace:
			return si.KubernetesNamespace < sj.KubernetesNamespace
		case si.KubernetesPodName != sj.KubernetesPodName:
			return si.KubernetesPodName < sj.KubernetesPodName
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

func GetSocketDefaultColumns() []string {
	// The columns that will be used in case the user does not specify which
	// specific columns they want to print through OutputConfig.
	return []string{
		"protocol",
		"local",
		"remote",
		"status",
	}
}

func NewSocketCmd(runCmd func(*cobra.Command, []string) error, flags *SocketFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "socket",
		Short: "Gather information about TCP and UDP sockets",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if flags.ParsedProtocol, err = types.ParseProtocol(flags.Protocol); err != nil {
				return err
			}

			return nil
		},
		RunE: runCmd,
	}

	var protocols []string
	for protocol := range types.ProtocolsMap {
		protocols = append(protocols, protocol)
	}

	cmd.PersistentFlags().StringVarP(
		&flags.Protocol,
		"proto",
		"",
		"all",
		fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
	)
	cmd.PersistentFlags().BoolVarP(
		&flags.Extended,
		"extend",
		"e",
		false,
		"Display other/more information (like socket inode)",
	)

	return cmd
}
