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
	commonsnapshot "github.com/kinvolk/inspektor-gadget/cmd/common/snapshot"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/spf13/cobra"
)

func NewSnapshotTraceConfig(gadgetName string, commonFlags *utils.CommonFlags, params map[string]string) *utils.TraceConfig {
	return &utils.TraceConfig{
		GadgetName:       gadgetName,
		Operation:        "collect",
		TraceOutputMode:  "Status",
		TraceOutputState: "Completed",
		Parameters:       params,
		CommonFlags:      commonFlags,
	}
}

func NewSnapshotCmd() *cobra.Command {
	cmd := commonsnapshot.NewCommonSnapshotCmd()

	cmd.AddCommand(newProcessCmd())
	cmd.AddCommand(newSocketCmd())

	return cmd
}
