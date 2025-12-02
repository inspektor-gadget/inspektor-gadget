// Copyright 2025 The Inspektor Gadget authors
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
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type Event struct {
	Foo   uint32 `json:"foo"`
	Fname string `json:"fname"`
}

func TestFlexString(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	t.Parallel()

	// As this gadget has / on this name, we need to use the full path to avoid
	// a lookup failure when running it.
	image := "ci/flex_string"
	if _, ok := os.LookupEnv("GADGET_REPOSITORY"); !ok {
		image = fmt.Sprintf("ghcr.io/inspektor-gadget/gadget/%s", image)
	}

	type testDef struct {
		name          string
		fname         string
		fnameSize     uint32
		expectedEvent *Event
	}

	const (
		path254 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn" // 254 characters
		path16  = "abcdefghijklmnop"                                                                                                                                                                                                                                         // 16 characters
	)

	tests := []testDef{
		{
			name:      "path254",
			fname:     path254,
			fnameSize: 255,
			expectedEvent: &Event{
				Foo:   42,
				Fname: path254,
			},
		},
		{
			name:      "path16",
			fname:     path16,
			fnameSize: 32,
			expectedEvent: &Event{
				Foo:   42,
				Fname: path16,
			},
		},
		{
			name:      "path254-trimmed",
			fname:     path254,
			fnameSize: 8,
			expectedEvent: &Event{
				Foo:   42,
				Fname: path254[:7], // 8 - 1 for null terminator
			},
		},
		{
			name:      "disabled",
			fname:     path254,
			fnameSize: 0,
			expectedEvent: &Event{
				Foo:   42,
				Fname: "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runnerConfig := &utilstest.RunnerConfig{}
			runner := utilstest.NewRunnerWithTest(t, runnerConfig)
			mntnsFilterMap := utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID)

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, generateEvent(test.fname))
				return nil
			}

			opts := gadgetrunner.GadgetRunnerOpts[Event]{
				Image:          image,
				Timeout:        5 * time.Second,
				OnGadgetRun:    onGadgetRun,
				MntnsFilterMap: mntnsFilterMap,
				ParamValues: map[string]string{
					"operator.oci.ebpf.fname-size": fmt.Sprintf("%d", test.fnameSize),
				},
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.RunGadget()

			utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, _ int) *Event {
				return test.expectedEvent
			})(t, runner.Info, 0, gadgetRunner.CapturedEvents)
		})
	}
}

// generateEvent simulates an event by opening and closing a file
func generateEvent(path string) func() error {
	return func() error {
		fd, err := unix.Open(path, 0, 0)
		if err == nil {
			unix.Close(fd)
		}

		return nil
	}
}
