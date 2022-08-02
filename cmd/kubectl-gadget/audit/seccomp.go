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

package audit

import (
	"encoding/json"
	"fmt"
	"os"

	commonaudit "github.com/kinvolk/inspektor-gadget/cmd/common/audit"
	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"github.com/spf13/cobra"
)

func newSeccompCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	cmd := &cobra.Command{
		Use:          "seccomp",
		Short:        "Audit syscalls according to the seccomp profile",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			parser := commonaudit.NewSeccompK8sParser(&commonFlags.OutputConfig)

			if commonFlags.OutputMode != commonutils.OutputModeJSON {
				fmt.Println(parser.BuildColumnsHeader())
			}

			config := &utils.TraceConfig{
				GadgetName:       "audit-seccomp",
				Operation:        "start",
				TraceOutputMode:  "Stream",
				TraceOutputState: "Started",
				CommonFlags:      &commonFlags,
			}

			transformEvent := func(line string) string {
				var e types.Event

				if err := json.Unmarshal([]byte(line), &e); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
					return ""
				}

				if e.Type != eventtypes.NORMAL {
					commonutils.ManageSpecialEvent(&e.Event, commonFlags.Verbose)
					return ""
				}

				return parser.TransformEvent(&e)
			}

			err := utils.RunTraceAndPrintStream(config, transformEvent)
			if err != nil {
				return commonutils.WrapInErrRunGadget(err)
			}

			return nil
		},
	}

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
