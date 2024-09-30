// Copyright 2024 The Inspektor Gadget authors
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

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

type ExpectedSnapshotProcessEvent struct {
	Comm      string `json:"comm"`
	Pid       int    `json:"pid"`
	Tid       int    `json:"tid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	ParentPid int    `json:"ppid"`
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (int, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedSnapshotProcessEvent) error
}

func TestSnapshotProcessGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	runnerConfig := &utilstest.RunnerConfig{}
	testCases := map[string]testDef{
		"captures_events_with_no_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedSnapshotProcessEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, sleepPid int) *ExpectedSnapshotProcessEvent {
					return &ExpectedSnapshotProcessEvent{
						Comm:      "sleep",
						Pid:       sleepPid,
						Tid:       sleepPid,
						Uid:       0,
						Gid:       0,
						ParentPid: info.Tid,
					}
				})(t, info, fd, events)
				return nil
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			capturedEvents := []ExpectedSnapshotProcessEvent{}
			var processId int
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			utilstest.RunWithRunner(t, runner, func() error {
				pid, _ := testCase.generateEvent()
				processId = pid
				return nil
			})
			timeout := 5 * time.Second
			const opPriority = 50000

			gadgetOperator := simple.New("gadget",
				simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
					for _, d := range gadgetCtx.GetDataSources() {
						jsonFormatter, err := igjson.New(d)
						require.NoError(t, err, "creating json formatter")
						d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
							event := &ExpectedSnapshotProcessEvent{}
							jsonOutput := jsonFormatter.Marshal(data)
							err := json.Unmarshal(jsonOutput, event)
							require.NoError(t, err, "unmarshalling event")

							// for current reference of the event
							fmt.Println("Captured data: ", string(jsonOutput))

							capturedEvents = append(capturedEvents, *event)

							return nil
						}, opPriority)

					}
					return nil
				}))

			gadgetCtx := gadgetcontext.New(
				context.Background(),
				// Use the snapshot_process gadget, this part will be made more modular in the future
				"ghcr.io/inspektor-gadget/gadget/snapshot_process:latest",
				gadgetcontext.WithDataOperators(
					ocihandler.OciHandler,
					gadgetOperator,
				),
				gadgetcontext.WithTimeout(timeout),
			)
			runtime := local.New()
			err := runtime.Init(nil)
			require.NoError(t, err, "initializing runtime")

			err = runtime.RunGadget(gadgetCtx, nil, nil)
			require.NoError(t, err, "running gadget")

			// Wait for the gadget to finish and then validate the events
			fd := processId
			testCase.validateEvent(t, runner.Info, fd, capturedEvents)
		})
	}
}
func generateEvent() (int, error) {
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("running command: %w", err)
	}
	return cmd.Process.Pid, nil
}
