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

	commonsnapshot "github.com/kinvolk/inspektor-gadget/cmd/common/snapshot"
	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
)

// SnapshotGadget represents a gadget belonging to the snapshot category.
type SnapshotGadget[Event commonsnapshot.SnapshotEvent] struct {
	commonsnapshot.SnapshotGadgetPrinter[Event]

	commonFlags *utils.CommonFlags
	runTracer   func(*localgadgetmanager.LocalGadgetManager, *containercollection.ContainerSelector) ([]Event, error)
}

// Run runs a SnapshotGadget and prints the output after parsing it using the
// SnapshotParser's methods.
func (g *SnapshotGadget[Event]) Run() error {
	localGadgetManager, err := localgadgetmanager.NewManager(g.commonFlags.RuntimeConfigs)
	if err != nil {
		return commonutils.WrapInErrManagerInit(err)
	}
	defer localGadgetManager.Close()

	// TODO: Improve filtering, see further details in
	// https://github.com/kinvolk/inspektor-gadget/issues/644.
	containerSelector := &containercollection.ContainerSelector{
		KubernetesContainerName: g.commonFlags.Containername,
	}

	allEvents, err := g.runTracer(localGadgetManager, containerSelector)
	if err != nil {
		return commonutils.WrapInErrGadgetTracerCreateAndRun(err)
	}

	return g.PrintEvents(allEvents)
}

func NewSnapshotCmd() *cobra.Command {
	cmd := commonsnapshot.NewCommonSnapshotCmd()

	cmd.AddCommand(newProcessCmd())

	// Socket gadget is disabled until we will enrich the socket information
	// with the container that is using the inode. For further details, see
	// https://github.com/kinvolk/inspektor-gadget/issues/744.
	// traceCmd.AddCommand(newSocketCmd())

	return cmd
}
