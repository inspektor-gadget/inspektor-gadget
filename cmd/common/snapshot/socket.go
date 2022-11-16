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

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/spf13/cobra"
)

type SocketFlags struct {
	Extended bool
	Protocol string

	ParsedProtocol types.Proto
}

type SocketParser struct {
	commonutils.GadgetParser[types.Event]
}

func newSocketParser(outputConfig *commonutils.OutputConfig, flags *SocketFlags, cols *columns.Columns[types.Event], options ...commonutils.Option) (SnapshotParser[types.Event], error) {
	col, _ := cols.GetColumn("inode")
	col.Visible = flags.Extended

	gadgetParser, err := commonutils.NewGadgetParser(outputConfig, cols, options...)
	if err != nil {
		return nil, commonutils.WrapInErrParserCreate(err)
	}

	return &SocketParser{
		GadgetParser: *gadgetParser,
	}, nil
}

func NewSocketParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *SocketFlags) (SnapshotParser[types.Event], error) {
	return newSocketParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.KubernetesTag))
}

func NewSocketParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *SocketFlags) (SnapshotParser[types.Event], error) {
	return newSocketParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.ContainerRuntimeTag))
}

func (p *SocketParser) TransformToColumns(e *types.Event) string {
	return p.GadgetParser.TransformIntoColumns(e)
}

func (p *SocketParser) GetOutputConfig() *commonutils.OutputConfig {
	return &commonutils.OutputConfig{
		OutputMode: commonutils.OutputModeColumns,
	}
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
