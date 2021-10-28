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
	"testing"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
)

func TestUtilsDotTrace(t *testing.T) {
	if integration != nil && !*integration {
		t.Skip("Skipping localIntegration test.")
	}
	// TODO(francis): Maybe create some resources (namespace, pod, etc.).
	commands := []struct {
		name              string
		config            utils.TraceConfig
		setTraceOperation string
		verbose           bool
		callback          func(results *gadgetv1alpha1.TraceList)
		transformLine     func(line string) string
	}{
		{
			name: "Test socket-collector",
			config: utils.TraceConfig{
				GadgetName:       "socket-collector",
				Operation:        "start",
				TraceOutputMode:  "Status",
				TraceOutputState: "Completed",
				CommonFlags: &utils.CommonFlags{
					Node:          "",
					AllNamespaces: true,
					Podname:       "",
					Containername: "",
					Label:         "",
					OutputMode:    utils.OutputModeColumns,
					Verbose:       false,
				},
			},
			setTraceOperation: "",
			// Empty function as we do not really care about printing.
			// We just want to check error code.
			callback:      func(results *gadgetv1alpha1.TraceList) {},
			transformLine: nil,
		},
	}

	failed := false
	for _, tt := range commands {
		t.Run(tt.name, func(t *testing.T) {
			if failed {
				t.Skip("Previous test failed.")
			}

			t.Logf("CreateTrace(%v)\n", tt.config)
			traceID, err := utils.CreateTrace(&tt.config)
			if err != nil {
				goto err
			}

			// Some gadget do not support other operation than start.
			// So, if setTraceOperation is empty, we just do no try to set it.
			if tt.setTraceOperation != "" {
				t.Logf("SetTraceOperation(%q, %q)\n", traceID, tt.setTraceOperation)
				err = utils.SetTraceOperation(traceID, tt.setTraceOperation)
				if err != nil {
					goto cleanup
				}
			}

			if tt.callback != nil {
				t.Logf("PrintTraceOutputFromStatus(%q, %v, %p)\n", traceID, tt.config.TraceOutputState, tt.callback)
				err = utils.PrintTraceOutputFromStatus(traceID, tt.config.TraceOutputState, tt.callback)
				if err != nil {
					goto cleanup
				}
			}

			if tt.transformLine != nil {
				t.Logf("PrintTraceOutputFromStream(%q, %v, %v, %p)\n", traceID, tt.config.TraceOutputState, tt.config.CommonFlags, tt.transformLine)
				err = utils.PrintTraceOutputFromStream(traceID, tt.config.TraceOutputMode, tt.config.CommonFlags, tt.transformLine)
				if err != nil {
					goto cleanup
				}
			}

			t.Logf("PrintAllTraces(%v)\n", tt.config)
			err = utils.PrintAllTraces(&tt.config)
			if err != nil {
				goto cleanup
			}

			t.Logf("DeleteTrace(%q)\n", traceID)
			err = utils.DeleteTrace(traceID)
			if err != nil {
				goto err
			}

			return
		cleanup:
			utils.DeleteTrace(traceID)
		err:
			failed = true
			t.Fatal(err)
		})
	}
}
