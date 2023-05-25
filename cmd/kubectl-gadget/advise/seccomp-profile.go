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

package advise

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"

	commonadvise "github.com/inspektor-gadget/inspektor-gadget/cmd/common/advise"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var seccompAdvisorStartCmd = &cobra.Command{
	Use:          "start",
	Short:        "Start to monitor the system calls",
	RunE:         runSeccompAdvisorStart,
	SilenceUsage: true,
}

var seccompAdvisorStopCmd = &cobra.Command{
	Use:          "stop <trace-id>",
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

func newSeccompProfileCmd() *cobra.Command {
	seccompProfileCmd := commonadvise.NewSeccompProfileCmd(nil)
	utils.AddCommonFlags(seccompProfileCmd, &params)

	seccompProfileCmd.AddCommand(seccompAdvisorStartCmd)
	seccompAdvisorStartCmd.PersistentFlags().StringVarP(&outputMode,
		"output-mode", "m",
		"terminal",
		"The trace output mode, possibles values are terminal and seccomp-profile.")
	seccompAdvisorStartCmd.PersistentFlags().StringVar(&profilePrefix,
		"profile-prefix", "",
		"Name prefix of the seccomp profile to be created when using --output-mode=seccomp-profile.\nNamespace can be specified by using namespace/profile-prefix.")

	seccompProfileCmd.AddCommand(seccompAdvisorStopCmd)
	seccompProfileCmd.AddCommand(seccompAdvisorListCmd)

	return seccompProfileCmd
}

func outputModeToTraceOutputMode(outputMode string) (gadgetv1alpha1.TraceOutputMode, error) {
	switch outputMode {
	case "terminal":
		return gadgetv1alpha1.TraceOutputModeStatus, nil
	case "seccomp-profile":
		return gadgetv1alpha1.TraceOutputModeExternalResource, nil
	default:
		return "", fmt.Errorf("%q is not an accepted value for --output-mode, possible values are: terminal (default) and seccomp-profile", outputMode)
	}
}

// runSeccompAdvisorStart starts monitoring of syscalls for the given
// parameters.
func runSeccompAdvisorStart(cmd *cobra.Command, args []string) error {
	if params.Podname == "" {
		return commonutils.WrapInErrMissingArgs("--podname")
	}

	traceOutputMode, err := outputModeToTraceOutputMode(outputMode)
	if err != nil {
		return err
	}

	if traceOutputMode != gadgetv1alpha1.TraceOutputModeExternalResource && profilePrefix != "" {
		return errors.New("you can only use --profile-prefix with --output seccomp-profile")
	}

	config := &utils.TraceConfig{
		GadgetName:        "seccomp",
		Operation:         gadgetv1alpha1.OperationStart,
		TraceOutputMode:   traceOutputMode,
		TraceOutput:       profilePrefix,
		TraceInitialState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:       &params,
	}

	traceID, err := utils.CreateTrace(config)
	if err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	fmt.Printf("%s\n", traceID)

	return nil
}

// getSeccompProfilesName returns the seccomp profiles name associated with the
// given as parameter traceID.
// Indeed, a seccomp profile created by seccomp-advisor gadgets has, in its
// Labels, the trace's id which created it.
func getSeccompProfilesName(traceID string) ([]string, error) {
	// seccompprofile does not provide an API to get Get, List, etc. seccomp
	// profiles, thus we need to make it ourselves.
	// To be able to retrieve seccompprofile, we need to add them to a scheme.
	scheme := runtime.NewScheme()
	seccompprofile.AddToScheme(scheme)

	// Get a manager on seccompprofile.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0", // TCP port can be set to "0" to disable the metrics serving
		ClientDisableCacheFor: []client.Object{
			// We need to disable cache otherwise we get the following error message:
			// the cache is not started, can not read objects
			// Since this manager will be created each time user interacts with the
			// CLI the cache will not persist, so there is not really advantages of
			// using a cache.
			&seccompprofile.SeccompProfile{},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating manager: %w", err)
	}

	// Get a client on seccompprofile.
	cli := mgr.GetClient()

	profilesList := &seccompprofile.SeccompProfileList{}
	err = cli.List(context.TODO(), profilesList, client.MatchingLabels{utils.GlobalTraceID: traceID})
	if err != nil {
		return nil, fmt.Errorf("listing seccomp profiles: %w", err)
	}

	var profilesName []string
	for _, profile := range profilesList.Items {
		profilesName = append(profilesName, profile.Name)
	}

	return profilesName, nil
}

// runSeccompAdvisorStop reports an already running trace which ID was given
// as parameter.
func runSeccompAdvisorStop(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return commonutils.WrapInErrMissingArgs("<trace-id>")
	}

	traceID := args[0]

	callback := func(traceOutputMode string, results []string) error {
		for _, r := range results {
			if traceOutputMode == string(gadgetv1alpha1.TraceOutputModeExternalResource) {
				profilesName, err := getSeccompProfilesName(traceID)
				if err != nil {
					return err
				}

				profilePlural := ""
				if len(profilesName) > 1 {
					profilePlural = "s"
				}

				fmt.Printf("Successfully created seccomp profile%s: %s\n", profilePlural, strings.Join(profilesName, ","))

				return nil
			}

			if r != "" {
				fmt.Printf("%v\n", r)
			}
		}

		return nil
	}

	// Maybe there is no trace with the given ID.
	// But it is better to try to delete something which does not exist than
	// leaking a resource.
	defer utils.DeleteTrace(traceID)

	err := utils.SetTraceOperation(traceID, string(gadgetv1alpha1.OperationGenerate))
	if err != nil {
		return commonutils.WrapInErrGenGadgetOutput(err)
	}

	// We stop the trace so its Status.State become Stopped.
	// Indeed, generate operation does not change value of Status.State.
	err = utils.SetTraceOperation(traceID, string(gadgetv1alpha1.OperationStop))
	if err != nil {
		return commonutils.WrapInErrStopGadget(err)
	}

	err = utils.PrintTraceOutputFromStatus(traceID, string(gadgetv1alpha1.TraceStateStopped), callback)
	if err != nil {
		return commonutils.WrapInErrGetGadgetOutput(err)
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

	err := utils.PrintAllTraces(config)
	if err != nil {
		return commonutils.WrapInErrListGadgetTraces(err)
	}

	return nil
}
