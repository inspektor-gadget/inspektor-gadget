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

package trace

import (
	"fmt"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"

	"github.com/spf13/cobra"
)

// All the gadgets within this package use this global variable, so let's
// declare it here.
var commonFlags utils.CommonFlags

func NewTraceCmd() *cobra.Command {
	TraceCmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace and print system events",
	}

	TraceCmd.AddCommand(newBindCmd())
	TraceCmd.AddCommand(newCapabilitiesCmd())
	TraceCmd.AddCommand(newDNSCmd())
	TraceCmd.AddCommand(newExecCmd())
	TraceCmd.AddCommand(newFsSlowerCmd())
	TraceCmd.AddCommand(newMountCmd())
	TraceCmd.AddCommand(newOOMKillCmd())
	TraceCmd.AddCommand(newOpenCmd())
	TraceCmd.AddCommand(newSignalCmd())
	TraceCmd.AddCommand(newSNICmd())
	TraceCmd.AddCommand(newTCPCmd())
	TraceCmd.AddCommand(newTcpconnectCmd())

	return TraceCmd
}

func printColumnsHeader(columnsWidth map[string]int, requestedCols []string) {
	var sb strings.Builder

	if len(requestedCols) == 0 {
		return
	}

	for _, col := range requestedCols {
		if width, ok := columnsWidth[col]; ok {
			sb.WriteString(fmt.Sprintf("%*s", width, strings.ToUpper(col)))
		}
		sb.WriteRune(' ')
	}

	fmt.Println(sb.String())
}
