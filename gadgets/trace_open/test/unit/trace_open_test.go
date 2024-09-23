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
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"

	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
)

type ExpectedTraceOpenEvent struct {
	Comm  string `json:"comm"`
	Pid   int    `json:"pid"`
	Tid   int    `json:"tid"`
	Uid   uint32 `json:"uid"`
	Gid   uint32 `json:"gid"`
	Fd    uint32 `json:"fd"`
	FName string `json:"fname"`
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (int, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error
}

func TestTraceOpenGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"captures_all_events": {
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  "unit.test",
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/dev/null",
					}
				})(t, info, fd, events)
				return nil
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			events := make(chan ExpectedTraceOpenEvent, 100)
			subscribed := make(chan bool, 1)
			wg.Add(1)
			go func() {
				timeout := 5 * time.Second
				const opPriority = 50000

				myOperator := simple.New("gadget", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
					for _, d := range gadgetCtx.GetDataSources() {
						jsonFormatter, _ := igjson.New(d)
						d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {

							jsonOutput := jsonFormatter.Marshal(data)

							event := &ExpectedTraceOpenEvent{}
							if err := json.Unmarshal(jsonOutput, event); err != nil {
								return fmt.Errorf("unmarshaling event: %w", err)
							}
							events <- *event
							return nil
						}, opPriority)

					}
					subscribed <- true
					return nil
				}))

				gadgetCtx := gadgetcontext.New(
					context.Background(),
					"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
					gadgetcontext.WithDataOperators(
						ocihandler.OciHandler,
						myOperator,
					),
					gadgetcontext.WithTimeout(timeout),
				)
				runtime := local.New()
				if err := runtime.Init(nil); err != nil {
					fmt.Errorf("runtime init: %w", err)
				}
				params := map[string]string{
					// Filter only events from the root user
					"operator.oci.ebpf.uid": "0",
				}

				if err := runtime.RunGadget(gadgetCtx, nil, params); err != nil {
					fmt.Errorf("running gadget: %w", err)
				}
				wg.Done()

			}()

			<-subscribed
			time.Sleep(1 * time.Second)
			close(subscribed)
			var fd int
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			utilstest.RunWithRunner(t, runner, func() error {
				fd, _ = testCase.generateEvent()
				return nil
			})

			wg.Wait()
			close(events)
			var capturedEvents []ExpectedTraceOpenEvent
			for event := range events {
				capturedEvents = append(capturedEvents, event)
			}
			testCase.validateEvent(t, runner.Info, fd, capturedEvents)
		})
	}
}

// generateEvent simulates an event by opening and closing a file
func generateEvent() (int, error) {
	fd, err := unix.Open("/dev/null", 0, 0)
	if err != nil {
		return 0, fmt.Errorf("opening file: %w", err)
	}

	// Close the file descriptor to simulate the event
	if err := unix.Close(fd); err != nil {
		return 0, fmt.Errorf("closing file: %w", err)
	}

	return fd, nil
}
