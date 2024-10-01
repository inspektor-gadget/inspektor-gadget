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
	"net"
	"sync"
	"testing"
	"time"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceTcpEvent struct {
	Comm string `json:"comm"`
	Pid  int    `json:"pid"`
	Tid  int    `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`
	Type string `json:"type"`

	MntNsId int `json:"mntns_id"`

	NetNsId int              `json:"netns_id"`
	Src     utils.L4Endpoint `json:"src"`
	Dst     utils.L4Endpoint `json:"dst"`
}

type testDef struct {
	addr          string
	port          int
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func(t *testing.T, addr string, port int)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceTcpEvent) error
}

func TestTraceOpenGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"captures_all_events": {
			addr:          "127.0.0.1",
			port:          9070,
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Comm:    info.Comm,
						Pid:     info.Pid,
						Tid:     info.Tid,
						Uid:     0,
						Gid:     0,
						Type:    "close",
						MntNsId: int(info.MountNsID),
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   6,
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9070,
							Proto:   6,
						},
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"captures_all_events2": {
			addr:          "127.0.0.1",
			port:          9160,
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Comm:    info.Comm,
						Pid:     info.Pid,
						Tid:     info.Tid,
						Uid:     0,
						Gid:     0,
						Type:    "close",
						MntNsId: int(info.MountNsID),
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   6,
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9160,
							Proto:   6,
						},
					}
				})(t, info, fd, events)
				return nil
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			capturedEvents := []ExpectedTraceTcpEvent{}
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			timeout := 5 * time.Second
			const opPriority = 50000
			var mutex sync.Mutex
			gadgetOperator := simple.New("gadget",
				// On init, subscribe to the data sources
				simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
					for _, d := range gadgetCtx.GetDataSources() {
						jsonFormatter, _ := igjson.New(d,
							// needed in order to get addr_raw converted to normal address.
							igjson.WithShowAll(true),
							igjson.WithPretty(true, "  "),
						)
						d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {

							event := &ExpectedTraceTcpEvent{}
							jsonOutput := jsonFormatter.Marshal(data)
							json.Unmarshal(jsonOutput, event)
							temp, _ := json.Marshal(event)

							// normalization of the Src Port can be made much clearer.
							utils.NormalizeInt(&event.Src.Port)

							mutex.Lock()
							capturedEvents = append(capturedEvents, *event)
							mutex.Unlock()
							// for current debugging
							fmt.Println("Captured Data: ", string(temp))
							return nil
						}, opPriority)

					}
					return nil
				}),
				// On start, generate an event that can be captured
				simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
					utilstest.RunWithRunner(t, runner, func() error {
						testCase.generateEvent(t, testCase.addr, testCase.port)
						return nil
					})
					return nil
				}))
			localManagerOp := &localmanager.LocalManager{}
			localManagerParams := localManagerOp.GlobalParamDescs().ToParams()
			localManagerParams.Get(localmanager.Runtimes).Set("docker")
			if err := localManagerOp.Init(localManagerParams); err != nil {
				require.NoError(t, err, "Initiatlizing Local Manager")
			}
			defer localManagerOp.Close()

			socketEnricherOp := &socketenricher.SocketEnricher{}
			if err := socketEnricherOp.Init(nil); err != nil {
				require.NoError(t, err, "Initiatlizing SocketEnricher")
			}
			defer socketEnricherOp.Close()

			// Use formatter to convert addr_raw to normal address.
			formatterOp := &formatters.FormattersOperator{}

			gadgetCtx := gadgetcontext.New(
				context.Background(),
				// Use the trace_open gadget, this part will be made more modular in the future
				"ghcr.io/inspektor-gadget/gadget/trace_tcp:latest",
				gadgetcontext.WithDataOperators(
					ocihandler.OciHandler,
					localManagerOp,
					socketEnricherOp,
					formatterOp,
					gadgetOperator,
				),
				gadgetcontext.WithTimeout(timeout),
			)
			runtime := local.New()
			err := runtime.Init(nil)
			require.NoError(t, err, "initializing runtime")
			params := map[string]string{
				"operator.oci.ebpf.uid":      "0",
				"operator.LocalManager.host": "true",
			}

			err = runtime.RunGadget(gadgetCtx, nil, params)
			require.NoError(t, err, "running gadget")

			// Wait for the gadget to finish and then validate the events
			testCase.validateEvent(t, runner.Info, 0, capturedEvents)
		})
	}
}

func generateEvent(t *testing.T, addr string, port int) {
	net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
}
