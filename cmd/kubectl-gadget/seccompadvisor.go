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
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

var seccompAdvisorCmd = &cobra.Command{
	Use:   "seccomp-advisor",
	Short: "Generate seccomp policies based on recorded syscalls activity",
}

var seccompAdvisorStartCmd = &cobra.Command{
	Use:          "start",
	Short:        "Start to monitor the system calls",
	RunE:         runSeccompAdvisorStart,
	SilenceUsage: true,
}

var seccompAdvisorStopCmd = &cobra.Command{
	Use:          "stop",
	Short:        "Stop monitoring and report the policies",
	RunE:         runSeccompAdvisorStop,
	SilenceUsage: true,
}

var seccompAdvisorListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List existing seccomp traces",
	RunE:         runSeccompAdvisorList,
	SilenceUsage: true,
}

var (
	outputMode    string
	profilePrefix string
)

func init() {
	// Add generic information.
	rootCmd.AddCommand(seccompAdvisorCmd)
	utils.AddCommonFlags(seccompAdvisorCmd, &params)

	seccompAdvisorCmd.AddCommand(seccompAdvisorStartCmd)
	seccompAdvisorStartCmd.PersistentFlags().StringVarP(&outputMode,
		"output-mode", "m",
		"terminal",
		"The trace output mode, possibles values are terminal and seccomp-profile.")
	seccompAdvisorStartCmd.PersistentFlags().StringVar(&profilePrefix,
		"profile-prefix", "",
		"Name prefix of the seccomp profile to be created when using --output-mode=seccomp-profile.\nNamespace can be specified by using namespace/profile-prefix.")

	seccompAdvisorCmd.AddCommand(seccompAdvisorStopCmd)
	seccompAdvisorCmd.AddCommand(seccompAdvisorListCmd)
}

func outputModeToTraceOutputMode(outputMode string) (string, error) {
	switch outputMode {
	case "terminal":
		return "Status", nil
	case "seccomp-profile":
		return "ExternalResource", nil
	default:
		return "", fmt.Errorf("%q is not an accepted value for --output-mode, possible values are: terminal (default) and seccomp-profile", outputMode)
	}
}

// runSeccompAdvisorStart starts monitoring of syscalls for the given
// parameters.
func runSeccompAdvisorStart(cmd *cobra.Command, args []string) error {
	if params.Podname == "" {
		return errors.New("usage: kubectl gadget seccompadvisor start -p podname")
	}

	traceOutputMode, err := outputModeToTraceOutputMode(outputMode)
	if err != nil {
		return err
	}

	if traceOutputMode != "ExternalResource" && profilePrefix != "" {
		return errors.New("you can only use --profile-prefix with --output seccomp-profile")
	}

	config := &utils.TraceConfig{
		GadgetName:        "seccomp",
		Operation:         "start",
		TraceOutputMode:   traceOutputMode,
		TraceOutput:       profilePrefix,
		TraceInitialState: "Started",
		CommonFlags:       &params,
	}

	traceID, err := utils.CreateTrace(config)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", traceID)

	return nil
}

// runSeccompAdvisorStop reports an already running trace which ID was given
// as parameter.
func runSeccompAdvisorStop(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kubectl gadget seccomp-advisor stop global-trace-id")
	}

	callback := func(results []gadgetv1alpha1.Trace) error {
		for _, i := range results {
			if i.Spec.OutputMode == "ExternalResource" {
				fmt.Printf("Successfully created seccomp profile\n")

				return nil
			}

			if i.Status.Output != "" {
				fmt.Printf("%v\n", i.Status.Output)
			}
		}

		return nil
	}

	traceID := args[0]

	// Maybe there is no trace with the given ID.
	// But it is better to try to delete something which does not exist than
	// leaking a resource.
	defer utils.DeleteTrace(traceID)

	err := utils.SetTraceOperation(traceID, "generate")
	if err != nil {
		return err
	}

	// We stop the trace so its Status.State become Stopped.
	// Indeed, generate operation does not change value of Status.State.
	err = utils.SetTraceOperation(traceID, "stop")
	if err != nil {
		return err
	}

	err = utils.PrintTraceOutputFromStatus(traceID, "Stopped", callback)
	if err != nil {
		return err
	}

	return nil
}

// runSeccompAdvisorList lists already running traces which config was given as
// parameter.
func runSeccompAdvisorList(cmd *cobra.Command, args []string) error {
	config := &utils.TraceConfig{
		GadgetName:  "seccomp",
		CommonFlags: &params,
	}

	return utils.PrintAllTraces(config)
}
