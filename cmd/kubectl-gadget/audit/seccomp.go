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

	"github.com/spf13/cobra"

	commonaudit "github.com/inspektor-gadget/inspektor-gadget/cmd/common/audit"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	seccompauditTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newSeccompCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		parser, err := commonutils.NewGadgetParserWithK8sInfo(
			&commonFlags.OutputConfig,
			seccompauditTypes.GetColumns(),
		)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		if commonFlags.OutputMode != commonutils.OutputModeJSON {
			fmt.Println(parser.BuildColumnsHeader())
		}

		config := &utils.TraceConfig{
			GadgetName:       "audit-seccomp",
			Operation:        gadgetv1alpha1.OperationStart,
			TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
			TraceOutputState: gadgetv1alpha1.TraceStateStarted,
			CommonFlags:      &commonFlags,
		}

		transformEvent := func(line string) string {
			var e seccompauditTypes.Event

			if err := json.Unmarshal([]byte(line), &e); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
				return ""
			}

			baseEvent := e.Event
			if baseEvent.Type != eventtypes.NORMAL {
				commonutils.ManageSpecialEvent(baseEvent, commonFlags.Verbose)
				return ""
			}

			switch commonFlags.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.Marshal(e)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
					return ""
				}

				return string(b)
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				return parser.TransformIntoColumns(&e)
			}

			return ""
		}

		err = utils.RunTraceAndPrintStream(config, transformEvent)
		if err != nil {
			return commonutils.WrapInErrRunGadget(err)
		}

		return nil
	}

	cmd := commonaudit.NewAuditCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
