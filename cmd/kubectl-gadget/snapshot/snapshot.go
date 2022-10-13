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

package snapshot

import (
	"encoding/json"

	"github.com/spf13/cobra"

	commonsnapshot "github.com/inspektor-gadget/inspektor-gadget/cmd/common/snapshot"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

// SnapshotGadget represents a gadget belonging to the snapshot category.
type SnapshotGadget[Event commonsnapshot.SnapshotEvent] struct {
	commonsnapshot.SnapshotGadgetPrinter[Event]

	name        string
	commonFlags *utils.CommonFlags
	params      map[string]string
}

// Run runs a SnapshotGadget and prints the output after parsing it using the
// SnapshotParser's methods.
func (g *SnapshotGadget[Event]) Run() error {
	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        gadgetv1alpha1.OperationCollect,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStatus,
		TraceOutputState: gadgetv1alpha1.TraceStateCompleted,
		CommonFlags:      g.commonFlags,
		Parameters:       g.params,
	}

	// This function is called when a snapshot gadget finishes without errors and
	// generates a list of results per node. It merges, sorts and print all of them
	// in the requested mode.
	callback := func(traceOutputMode string, results []string) error {
		allEvents := []Event{}

		for _, r := range results {
			if len(r) == 0 {
				continue
			}

			var events []Event
			if err := json.Unmarshal([]byte(r), &events); err != nil {
				return commonutils.WrapInErrUnmarshalOutput(err, r)
			}
			allEvents = append(allEvents, events...)
		}

		return g.PrintEvents(allEvents)
	}

	if err := utils.RunTraceAndPrintStatusOutput(config, callback); err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	return nil
}

func NewSnapshotCmd() *cobra.Command {
	cmd := commonsnapshot.NewCommonSnapshotCmd()

	cmd.AddCommand(newProcessCmd())
	cmd.AddCommand(newSocketCmd())

	return cmd
}
