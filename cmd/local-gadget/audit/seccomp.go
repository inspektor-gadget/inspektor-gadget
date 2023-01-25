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

package audit

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	commonaudit "github.com/inspektor-gadget/inspektor-gadget/cmd/common/audit"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/tracer"
	seccompauditTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newSeccompCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
		if err != nil {
			return commonutils.WrapInErrManagerInit(err)
		}
		defer localGadgetManager.Close()

		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(
			&commonFlags.OutputConfig,
			seccompauditTypes.GetColumns(),
		)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		if commonFlags.OutputMode != commonutils.OutputModeJSON {
			fmt.Println(parser.BuildColumnsHeader())
		}

		eventCallback := func(event *seccompauditTypes.Event) {
			baseEvent := event.Event
			if baseEvent.Type != eventtypes.NORMAL {
				commonutils.HandleSpecialEvent(&baseEvent, commonFlags.Verbose)
				return
			}

			switch commonFlags.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.Marshal(event)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
					return
				}

				fmt.Println(string(b))
			case commonutils.OutputModeCustomColumns:
				fmt.Println(parser.TransformIntoColumns(event))
			}
		}

		// TODO: Improve filtering, see further details in
		// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
		containerSelector := containercollection.ContainerSelector{
			Name: commonFlags.Containername,
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := localGadgetManager.CreateMountNsMap(containerSelector)
		if err != nil {
			return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}
		defer localGadgetManager.RemoveMountNsMap()

		config := &tracer.Config{
			MountnsMap: mountnsmap,
		}

		tracer, err := tracer.NewTracer(config, localGadgetManager, eventCallback)
		if err != nil {
			return fmt.Errorf("creating tracer: %w", err)
		}
		defer tracer.Close()

		utils.WaitForEnd(&commonFlags)
		return nil
	}

	cmd := commonaudit.NewAuditCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
