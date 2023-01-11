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
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	columnssort "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
)

type SocketFlags struct {
	Extended bool
	Protocol string

	ParsedProtocol types.Proto
}

type SocketParser struct {
	commonutils.GadgetParser[types.Event]
	outputConfig *commonutils.OutputConfig
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
		outputConfig: outputConfig,
	}, nil
}

func NewSocketParserWithK8sInfo(outputConfig *commonutils.OutputConfig, flags *SocketFlags) (SnapshotParser[types.Event], error) {
	return newSocketParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.KubernetesTag))
}

func NewSocketParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig, flags *SocketFlags) (SnapshotParser[types.Event], error) {
	return newSocketParser(outputConfig, flags, types.GetColumns(), commonutils.WithMetadataTag(commonutils.ContainerRuntimeTag))
}

func (s *SocketParser) GetOutputConfig() *commonutils.OutputConfig {
	return s.outputConfig
}

func (s *SocketParser) SortEvents(allSockets []*types.Event) {
	columnssort.SortEntries(types.GetColumns().GetColumnMap(), allSockets,
		[]string{"node", "namespace", "pod", "proto", "status", "localAddr", "remoteAddr", "localPort", "remotePort", "inode"})
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
