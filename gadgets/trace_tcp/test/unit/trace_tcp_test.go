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
	"fmt"
	"net"
	"testing"
	"time"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceTcpEvent struct {
	Proc ebpftypes.Process `json:"proc"`

	Type    string           `json:"type"`
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

func TestTraceTcpGadget(t *testing.T) {
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
						Proc:    info.Proc,
						Type:    "close",
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   "TCP",
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9070,
							Proto:   "TCP",
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
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			normalizeEvent := func(event *ExpectedTraceTcpEvent) {
				// Src port varies, so we normalize it
				// TODO: Add a generateEvent function that allows us to test specific src port too.
				utils.NormalizeInt(&event.Src.Port)
			}

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					testCase.generateEvent(t, testCase.addr, testCase.port)
					return nil
				})
				return nil
			}

			Opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceTcpEvent]{
				Image:          "trace_tcp",
				Timeout:        5 * time.Second,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, Opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, 0, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent(t *testing.T, addr string, port int) {
	net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
}
