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
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile/types"

	"github.com/spf13/cobra"
)

var (
	profileKernel bool
	profileUser   bool
)

var cpuTraceConfig = &utils.TraceConfig{
	GadgetName:        "profile",
	TraceOutputMode:   "Status",
	TraceOutputState:  "Completed",
	TraceInitialState: "Started",
	CommonFlags:       &params,
}

var profileCmd = &cobra.Command{
	Use:          "cpu",
	Short:        "Analyze CPU performance by sampling stack traces",
	RunE:         runProfileCPU,
	SilenceUsage: true,
}

func init() {
	ProfilerCmd.AddCommand(profileCmd)
	utils.AddCommonFlags(profileCmd, &params)

	profileCmd.PersistentFlags().BoolVarP(
		&profileUser,
		"user",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	profileCmd.PersistentFlags().BoolVarP(
		&profileKernel,
		"kernel",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)
}

func runProfileCPU(cmd *cobra.Command, args []string) error {
	if profileUser && profileKernel {
		return utils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
	}

	cpuTraceConfig.Parameters = map[string]string{}

	if profileUser {
		cpuTraceConfig.Parameters[types.ProfileUserParam] = ""
	}

	if profileKernel {
		cpuTraceConfig.Parameters[types.ProfileKernelParam] = ""
	}

	cpuTraceConfig.Operation = "start"
	traceID, err := utils.CreateTrace(cpuTraceConfig)
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
		fmt.Printf("Capturing stack traces...")
	} else {
		fmt.Printf("Capturing stack traces... Hit Ctrl-C to end.")
	}

	<-c

	fmt.Println()
	err = utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return utils.WrapInErrStopGadget(err)
	}

	displayResultsCallback := func(traces []gadgetv1alpha1.Trace) error {
		for _, trace := range traces {
			fmt.Printf("%v\n", trace.Status.Output)
		}

		return nil
	}

	err = utils.PrintTraceOutputFromStatus(traceID,
		cpuTraceConfig.TraceOutputState, displayResultsCallback)
	if err != nil {
		return utils.WrapInErrGetGadgetOutput(err)
	}

	return nil
}
