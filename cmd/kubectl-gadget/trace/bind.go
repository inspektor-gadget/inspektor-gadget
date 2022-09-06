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
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	commontrace "github.com/kinvolk/inspektor-gadget/cmd/common/trace"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/bind/types"
)

func newBindCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontrace.BindFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		portsStringSlice := []string{}
		for _, port := range flags.ValidatedTargetPorts {
			portsStringSlice = append(portsStringSlice, strconv.FormatUint(uint64(port), 10))
		}

		bindGadget := &TraceGadget[types.Event]{
			name:        "bindsnoop",
			commonFlags: &commonFlags,
			parser:      commontrace.NewBindParserWithK8sInfo(&commonFlags.OutputConfig),
			params: map[string]string{
				"pid":           strconv.FormatUint(uint64(flags.TargetPid), 10),
				"ports":         strings.Join(portsStringSlice, ","),
				"ignore_errors": strconv.FormatBool(flags.IgnoreErrors),
			},
		}

		return bindGadget.Run()
	}

	cmd := commontrace.NewBindCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
