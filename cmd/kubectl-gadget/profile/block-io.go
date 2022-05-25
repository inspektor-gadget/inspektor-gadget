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
	"os"
	"os/signal"
	"strings"
	"time"

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
	Use:          "block-io",
	Short:        "Analyze block I/O performance through a latency distribution",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runBiolatency,
}

func init() {
	ProfilerCmd.AddCommand(biolatencyCmd)

	utils.AddCommonFlags(biolatencyCmd, &params)
}

func runBiolatency(cmd *cobra.Command, args []string) error {
	// Biolatency does not support filtering so we need to avoid adding
	// the default namespace configured in the kubeconfig file.
	if params.Namespace != "" && !params.NamespaceOverridden {
		params.Namespace = ""
	}

	if params.Node == "" {
		return utils.WrapInErrMissingArgs("--node")
	}

	biolatencyTraceConfig.Operation = "start"
	traceID, err := utils.CreateTrace(biolatencyTraceConfig)
	if err != nil {
		return utils.WrapInErrRunGadget(err)
	}

	defer utils.DeleteTrace(traceID)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	if params.Timeout != 0 {
		go func() {
			time.Sleep(time.Duration(params.Timeout) * time.Second)
			c <- os.Interrupt
		}()
		fmt.Printf("Tracing block device I/O...")
	} else {
		fmt.Printf("Tracing block device I/O... Hit Ctrl-C to end.")
	}

	<-c

	fmt.Println()
	err = utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return utils.WrapInErrStopGadget(err)
	}

	displayResultsCallback := func(results []gadgetv1alpha1.Trace) error {
		if len(results) != 1 {
			return errors.New("there should be only one result because biolatency runs on one node at a time")
		}

		// remove message printed by BCC tracer to avoid printing it twice
		ret := strings.ReplaceAll(results[0].Status.Output,
			"Tracing block device I/O... Hit Ctrl-C to end.\n", "")

		fmt.Printf("%s", ret)
		return nil
	}

	err = utils.PrintTraceOutputFromStatus(traceID,
		biolatencyTraceConfig.TraceOutputState, displayResultsCallback)
	if err != nil {
		return utils.WrapInErrGetGadgetOutput(err)
	}

	return nil
}
