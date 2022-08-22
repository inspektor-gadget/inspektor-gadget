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

package utils

import (
	"fmt"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
)

// TraceConfig is used to contain information used to manage a trace.
type TraceConfig struct {
	// GadgetName is gadget name, e.g. socket-collector.
	GadgetName string

	// TraceOutputState is the state in which the trace can output information.
	// For example, trace for *-collector gadget contains output while in
	// Completed state.
	// But other gadgets, like dns, can contain output only in Started state.
	TraceOutputState gadgetv1alpha1.TraceState

	// Parameters is used to pass specific gadget configurations.
	Parameters map[string]string

	// CommonFlags is used to hold parameters given on the command line interface.
	CommonFlags *CommonFlags
}

func RunTraceAndPrintStatusOutput(config *TraceConfig, customResultsDisplay func(string, []string) error) error {
	traceName := "trace_" + config.GadgetName

	localGadgetManager, err := localgadgetmanager.NewManager(config.CommonFlags.RuntimeConfigs)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}
	defer localGadgetManager.Close()

	err = localGadgetManager.AddTracer(
		config.GadgetName,
		traceName,
		config.CommonFlags.Containername,
		"",
		config.Parameters,
	)
	if err != nil {
		return fmt.Errorf("failed to add trace: %w", err)
	}
	defer localGadgetManager.Delete(traceName)

	operations := localGadgetManager.ListOperations(traceName)
	if len(operations) == 1 {
		err = localGadgetManager.Operation(traceName, operations[0])
	} else {
		err = localGadgetManager.Operation(traceName, gadgetv1alpha1.OperationStart)
	}

	if err != nil {
		return fmt.Errorf("failed to run requested operation: %w", err)
	}

	if err = localGadgetManager.CheckStatus(traceName, config.TraceOutputState); err != nil {
		return err
	}

	return localGadgetManager.DisplayOutput(traceName, customResultsDisplay)
}
