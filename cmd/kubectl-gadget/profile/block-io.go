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

package profile

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

var biolatencyTraceConfig = &utils.TraceConfig{
	GadgetName:        "biolatency",
	TraceOutputMode:   "Status",
	TraceOutputState:  "Completed",
	TraceInitialState: "Started",
	CommonFlags:       &params,
}

var biolatencyCmd = &cobra.Command{
	Use:   "block-io",
	Short: "Analyze block I/O performance through a latency distribution",
}

var biolatencyStartCmd = &cobra.Command{
	Use:          "start",
	Short:        "Start monitor the block device I/O (disk I/O) and record the distribution of I/O latency (time)",
	RunE:         runBiolatencyStart,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Biolatency does not support filtering so we need to avoid adding
		// the default namespace configured in the kubeconfig file.
		if params.Namespace != "" && !params.NamespaceOverridden {
			params.Namespace = ""
		}
		return nil
	},
}

var biolatencyStopCmd = &cobra.Command{
	Use:          "stop <trace-id>",
	Short:        "Stop monitoring and generate a report (a histogram graph) with the distribution of block device I/O latency",
	RunE:         runBiolatencyStop,
	SilenceUsage: true,
}

var biolatencyListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List the currently running biolatency traces",
	RunE:         runBiolatencyList,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
}

func init() {
	biolatencyCmd.AddCommand(biolatencyStartCmd)
	biolatencyCmd.AddCommand(biolatencyStopCmd)
	biolatencyCmd.AddCommand(biolatencyListCmd)

	ProfilerCmd.AddCommand(biolatencyCmd)

	// Common flags are meaningless for list and stop sub-commands
	utils.AddCommonFlags(biolatencyStartCmd, &params)
}

func runBiolatencyStart(cmd *cobra.Command, args []string) error {
	if params.Node == "" {
		return utils.WrapInErrMissingArgs("--node")
	}

	biolatencyTraceConfig.Operation = "start"
	traceID, err := utils.CreateTrace(biolatencyTraceConfig)
	if err != nil {
		return utils.WrapInErrRunGadget(err)
	}

	fmt.Printf("%s\n", traceID)

	return nil
}

func runBiolatencyStop(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return utils.WrapInErrMissingArgs("<trace-id>")
	}
	traceID := args[0]

	err := utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return utils.WrapInErrStopGadget(err)
	}

	displayResultsCallback := func(results []gadgetv1alpha1.Trace) error {
		if len(results) != 1 {
			return errors.New("there should be only one result because biolatency runs on one node at a time")
		}

		fmt.Printf("%v", results[0].Status.Output)
		return nil
	}

	defer utils.DeleteTrace(traceID)

	err = utils.PrintTraceOutputFromStatus(traceID,
		biolatencyTraceConfig.TraceOutputState, displayResultsCallback)
	if err != nil {
		return utils.WrapInErrGetGadgetOutput(err)
	}

	return nil
}

func runBiolatencyList(cmd *cobra.Command, args []string) error {
	err := utils.PrintAllTraces(biolatencyTraceConfig)
	if err != nil {
		return utils.WrapInErrListGadgetTraces(err)
	}
	return nil
}
