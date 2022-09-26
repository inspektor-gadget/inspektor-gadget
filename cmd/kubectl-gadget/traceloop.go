// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

var traceloopCmd = &cobra.Command{
	Use:   "traceloop",
	Short: "Get strace-like logs of a pod from the past",
}

var traceloopListCmd = &cobra.Command{
	Use:   "list",
	Short: "list possible traces",
	RunE:  runTraceloopList,
}

var traceloopStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start traceloop",
	RunE:  runTraceloopStart,
}

var traceloopStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop traceloop",
	RunE:  runTraceloopStop,
}

var traceloopShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show one trace",
	RunE:  runTraceloopShow,
}

var (
	optionListFull          bool
	optionListAllNamespaces bool
	optionListNoHeaders     bool
)

func init() {
	rootCmd.AddCommand(traceloopCmd)
	utils.AddCommonFlags(traceloopCmd, &params)

	traceloopCmd.AddCommand(traceloopStartCmd)
	traceloopCmd.AddCommand(traceloopStopCmd)
	traceloopCmd.AddCommand(traceloopListCmd)
	traceloopCmd.AddCommand(traceloopShowCmd)
}

const (
	traceloopStateAnnotation = "traceloop.kinvolk.io/state"
)

func runTraceloopStart(cmd *cobra.Command, args []string) error {
	// Create traceloop trace
	traceID, err := utils.CreateTrace(&utils.TraceConfig{
		GadgetName:      "traceloop",
		Operation:       gadgetv1alpha1.OperationStart,
		TraceOutputMode: gadgetv1alpha1.TraceOutputModeStream,
		CommonFlags:     &params,
	})
	if err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	fmt.Printf("%s\n", traceID)

	return nil
}

func runTraceloopStop(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return commonutils.WrapInErrMissingArgs("<trace-id>")
	}

	traceID := args[0]

	// Maybe there is no trace with the given ID.
	// But it is better to try to delete something which does not exist than
	// leaking a resource.
	defer utils.DeleteTrace(traceID)

	err := utils.SetTraceOperation(traceID, string(gadgetv1alpha1.OperationStop))
	if err != nil {
		return commonutils.WrapInErrStopGadget(err)
	}

	return nil
}

func runTraceloopList(cmd *cobra.Command, args []string) error {
	config := &utils.TraceConfig{
		GadgetName:  "traceloop",
		CommonFlags: &params,
	}

	err := utils.PrintAllTraces(config)
	if err != nil {
		return commonutils.WrapInErrListGadgetTraces(err)
	}

	return nil
}

func runTraceloopShow(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return commonutils.WrapInErrMissingArgs("<trace-id>")
	}

	traceID := args[0]

	transformLine := func(line string) string {
		return line
	}

	traces, err := utils.ListTracesByGadgetName("traceloop")
	if err != nil {
		return err
	}

	for _, trace := range traces {
		if trace.Labels[utils.GlobalTraceID] != traceID {
			continue
		}

		err := utils.RunTraceAndPrintStream(
			&utils.TraceConfig{
				GadgetName:      "traceloop",
				Operation:       gadgetv1alpha1.OperationCollect,
				TraceOutputMode: gadgetv1alpha1.TraceOutputModeStream,
				CommonFlags:     &params,
				Parameters: map[string]string{
					// We will not create a traceloop/gadget.go:Trace for this specific
					// trace CRD.
					// In place, we will use the traceloop/gadget.go:Trace which was
					// created when called traceloop/gadget.go:Start().
					// To do so, we use this name to get the traceloop/gadget.go:Trace
					// from the map.
					// Nonetheless when Start()'ed, the used name was the namespaced one:
					// https://github.com/inspektor-gadget/inspektor-gadget/blob/9532d507bbd741f6202e1945db20cb6d1471e0ac/pkg/controllers/trace_controller.go#L253
					// So, we need to use the namespace here too.
					"name": fmt.Sprintf("%s/%s", trace.Namespace, trace.Name),
				},
			},
			transformLine,
		)
		if err != nil {
			return err
		}
	}

	return nil
}
