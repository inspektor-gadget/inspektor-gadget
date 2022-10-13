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
	"github.com/spf13/cobra"

	commonsnapshot "github.com/inspektor-gadget/inspektor-gadget/cmd/common/snapshot"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	processTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
	processTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

func newProcessCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commonsnapshot.ProcessFlags

	runCmd := func(*cobra.Command, []string) error {
		processGadget := &SnapshotGadget[processTypes.Event]{
			SnapshotGadgetPrinter: commonsnapshot.SnapshotGadgetPrinter[processTypes.Event]{
				Parser: commonsnapshot.NewProcessParserWithRuntimeInfo(&commonFlags.OutputConfig, &flags),
			},
			commonFlags: &commonFlags,
			runTracer: func(localGadgetManager *localgadgetmanager.LocalGadgetManager, containerSelector *containercollection.ContainerSelector) ([]processTypes.Event, error) {
				// Create mount namespace map to filter by containers
				mountnsmap, err := localGadgetManager.CreateMountNsMap(*containerSelector)
				if err != nil {
					return nil, commonutils.WrapInErrManagerCreateMountNsMap(err)
				}
				defer localGadgetManager.RemoveMountNsMap()

				return processTracer.RunCollector(&localGadgetManager.ContainerCollection, mountnsmap)
			},
		}

		return processGadget.Run()
	}

	cmd := commonsnapshot.NewProcessCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
