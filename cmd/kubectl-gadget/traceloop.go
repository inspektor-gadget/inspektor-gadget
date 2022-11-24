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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	traceloopTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var traceloopCmd = &cobra.Command{
	Use:   "traceloop",
	Short: "Get strace-like logs of a container from the past",
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

var traceloopDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete one trace",
	RunE:  runTraceloopDelete,
}

func init() {
	rootCmd.AddCommand(traceloopCmd)
	utils.AddCommonFlags(traceloopCmd, &params)

	traceloopCmd.AddCommand(traceloopStartCmd)
	traceloopCmd.AddCommand(traceloopStopCmd)
	traceloopCmd.AddCommand(traceloopListCmd)
	traceloopCmd.AddCommand(traceloopShowCmd)
	traceloopCmd.AddCommand(traceloopDeleteCmd)
}

func runTraceloopStart(cmd *cobra.Command, args []string) error {
	traces, err := utils.ListTracesByGadgetName("traceloop")
	if err != nil {
		return err
	}

	if len(traces) != 0 {
		return errors.New("traceloop was already started")
	}

	if params.NamespaceOverridden {
		return commonutils.WrapInErrInvalidArg("--namespace / -n", fmt.Errorf("this gadget cannot filter by namespace"))
	}

	if params.Podname != "" {
		return commonutils.WrapInErrInvalidArg("--podname / -p", fmt.Errorf("this gadget cannot filter by pod name"))
	}

	if params.Containername != "" {
		return commonutils.WrapInErrInvalidArg("--containername / -c", fmt.Errorf("this gadget cannot filter by container name"))
	}

	// At the moment, there could be only one instance of traceloop running at a
	// given time, so it should cover all existing namespaces.
	// TODO Make traceloop accept -n option, this would need to care when
	// removing from map of perf buffer to avoid reading non existing data.
	params.AllNamespaces = true
	params.Namespace = ""

	// Create traceloop trace
	_, err = utils.CreateTrace(&utils.TraceConfig{
		GadgetName:      "traceloop",
		Operation:       gadgetv1alpha1.OperationStart,
		TraceOutputMode: gadgetv1alpha1.TraceOutputModeStatus,
		CommonFlags:     &params,
		// This label permits us to differentiate between the global and long lived
		// tracer and the short lived ones used to collect information.
		AdditionalLabels: map[string]string{
			"type": "global",
		},
	})
	if err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	return nil
}

func runTraceloopStop(cmd *cobra.Command, args []string) error {
	traceList, err := utils.GetTraceListFromOptions(metav1.ListOptions{
		LabelSelector: "gadgetName=traceloop,type=global",
	})
	if err != nil {
		return err
	}

	traces := traceList.Items
	if len(traces) == 0 {
		return errors.New("please start traceloop before stopping it")
	}

	traceID := traces[0].Labels[utils.GlobalTraceID]

	// Maybe there is no trace with the given ID.
	// But it is better to try to delete something which does not exist than
	// leaking a resource.
	defer utils.DeleteTrace(traceID)

	err = utils.SetTraceOperation(traceID, string(gadgetv1alpha1.OperationStop))
	if err != nil {
		return commonutils.WrapInErrStopGadget(err)
	}

	return nil
}

func runTraceloopList(cmd *cobra.Command, args []string) error {
	traceList, err := utils.GetTraceListFromOptions(metav1.ListOptions{
		LabelSelector: "gadgetName=traceloop,type=global",
	})
	if err != nil {
		return err
	}

	traces := traceList.Items
	if len(traces) == 0 {
		return errors.New("please start traceloop before trying to list traces")
	}

	parser, err := commonutils.NewGadgetParserWithK8sInfo(&params.OutputConfig, traceloopTypes.GetInfoColumns())
	if err != nil {
		return err
	}

	if params.OutputMode != commonutils.OutputModeJSON {
		fmt.Println(parser.BuildColumnsHeader())
	}

	for _, trace := range traces {
		var infos []traceloopTypes.TraceloopInfo

		err = json.Unmarshal([]byte(trace.Status.Output), &infos)
		if err != nil {
			return err
		}

		for _, info := range infos {
			info.Node = trace.Spec.Node

			switch params.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.Marshal(info)
				if err != nil {
					return commonutils.WrapInErrMarshalOutput(err)
				}

				fmt.Println(string(b))
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				fmt.Println(parser.TransformIntoColumns(&info))
			}
		}
	}

	return nil
}

func runTraceloopShow(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return commonutils.WrapInErrMissingArgs("<container-id>")
	}

	id := args[0]

	traceList, err := utils.GetTraceListFromOptions(metav1.ListOptions{
		LabelSelector: "gadgetName=traceloop,type=global",
	})
	if err != nil {
		return err
	}

	parser, err := commonutils.NewGadgetParserWithK8sInfo(&params.OutputConfig, traceloopTypes.GetColumns())
	if err != nil {
		return err
	}

	if params.OutputMode != commonutils.OutputModeJSON {
		fmt.Println(parser.BuildColumnsHeader())
	}

	var traceID string

	transformEvent := func(line string) string {
		var events []traceloopTypes.Event
		if err := json.Unmarshal([]byte(line), &events); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
			return ""
		}

		for _, event := range events {
			baseEvent := event.GetBaseEvent()
			if baseEvent.Type != eventtypes.NORMAL {
				commonutils.HandleSpecialEvent(baseEvent, params.Verbose)
				return ""
			}

			switch params.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.Marshal(event)
				if err != nil {
					fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
					return ""
				}

				fmt.Println(string(b))
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				fmt.Println(parser.TransformIntoColumns(&event))
			}
		}

		// HACK Take a look at gadget.go.
		utils.DeleteTrace(traceID)

		os.Exit(0)

		return ""
	}

	traces := traceList.Items
	for _, trace := range traces {
		var infos []traceloopTypes.TraceloopInfo

		err = json.Unmarshal([]byte(trace.Status.Output), &infos)
		if err != nil {
			return err
		}

		containerID := ""
		for _, info := range infos {
			// The CLI can give a shorter ID (e.g. 12 characters long), so we need to
			// test if the long container ID starts with the short one to use the long
			// one in the rest of the code.
			if strings.HasPrefix(info.ContainerID, id) {
				containerID = info.ContainerID

				break
			}
		}

		// The container of interest does not depend on the current trace.
		if len(containerID) == 0 {
			continue
		}

		var err error

		// We want to create only stream trace which is on the same node than
		// corresponding trace.
		params.Node = trace.Spec.Node

		traceID, err = utils.CreateTrace(&utils.TraceConfig{
			GadgetName:       "traceloop",
			Operation:        gadgetv1alpha1.OperationCollect,
			TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
			TraceOutputState: gadgetv1alpha1.TraceStateCompleted,
			CommonFlags:      &params,
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
				"name":        fmt.Sprintf("%s/%s", trace.Namespace, trace.Name),
				"containerID": containerID,
			},
			AdditionalLabels: map[string]string{
				"type": "collecting",
			},
		})
		if err != nil {
			return fmt.Errorf("error creating trace: %w", err)
		}

		utils.SigHandler(&traceID, params.OutputMode != commonutils.OutputModeJSON)

		err = utils.PrintTraceOutputFromStream(traceID, string(gadgetv1alpha1.TraceStateCompleted), &params, transformEvent)
		if err != nil {
			return err
		}

		// There is only one container with the given ID, so only one trace which
		// handles this container.
		return nil
	}

	return fmt.Errorf("no trace associated with container ID %v exists", id)
}

func runTraceloopDelete(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return commonutils.WrapInErrMissingArgs("<container-id>")
	}

	id := args[0]

	traceList, err := utils.GetTraceListFromOptions(metav1.ListOptions{
		LabelSelector: "gadgetName=traceloop,type=global",
	})
	if err != nil {
		return err
	}

	traces := traceList.Items
	for _, trace := range traces {
		var infos []traceloopTypes.TraceloopInfo

		err = json.Unmarshal([]byte(trace.Status.Output), &infos)
		if err != nil {
			return err
		}

		containerID := ""
		for _, info := range infos {
			// The CLI can give a shorter ID (e.g. 12 characters long), so we need to
			// test if the long container ID starts with the short one to use the long
			// one in the rest of the code.
			if strings.HasPrefix(info.ContainerID, id) {
				containerID = info.ContainerID

				break
			}
		}

		// The container of interest does not depend on the current trace.
		if len(containerID) == 0 {
			continue
		}

		// We want to create only trace which is on the same node than
		// corresponding trace.
		params.Node = trace.Spec.Node

		traceID, err := utils.CreateTrace(&utils.TraceConfig{
			GadgetName:       "traceloop",
			Operation:        gadgetv1alpha1.OperationDelete,
			TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStatus,
			TraceOutputState: gadgetv1alpha1.TraceStateCompleted,
			CommonFlags:      &params,
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
				"name":        fmt.Sprintf("%s/%s", trace.Namespace, trace.Name),
				"containerID": containerID,
			},
			AdditionalLabels: map[string]string{
				"type": "deleting",
			},
		})
		if err != nil {
			return fmt.Errorf("error creating trace: %w", err)
		}

		defer utils.DeleteTrace(traceID)

		err = utils.PrintTraceOutputFromStatus(traceID, string(gadgetv1alpha1.TraceStateCompleted), func(_ string, _ []string) error {
			return nil
		})
		if err != nil {
			return err
		}

		// There is only one container with the given ID, so only one trace which
		// handles this container.
		return nil
	}

	return fmt.Errorf("no trace associated with container ID %v exists", id)
}
