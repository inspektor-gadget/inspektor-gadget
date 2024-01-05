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

package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runner"
)

func StartGadgetRunner(t *testing.T, image string, events *[]string, finishWG *sync.WaitGroup) *runner.Runner {
	gadgetRunner, err := runner.NewRunner(image,
		runner.WithContext(context.Background()),
		// Timeout is set higher than the container "timeouts" in the test steps
		runner.WithTimeout(30*time.Second),
		runner.WithPullPolicy(oci.PullImageNever),
	)
	require.NoError(t, err)
	require.NotNil(t, gadgetRunner)

	go require.NoError(t, gadgetRunner.Run())
	go DrainEvents(t, gadgetRunner, events, finishWG)

	return gadgetRunner
}

func TestRunnerCloseWithoutFinish(t *testing.T) {
	t.Parallel()
	cn := "test-runner-close-without-finish"

	// Pull image before running the test
	image := "ghcr.io/inspektor-gadget/gadget/trace_open"
	_, err := oci.PullGadgetImage(context.Background(), image, &oci.AuthOptions{AuthFile: oci.DefaultAuthFile})
	require.NoError(t, err, "Pulling the gadget image should succeed")

	var events []string
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	runner := StartGadgetRunner(t, image, &events, finishWG)

	testSteps := []TestStep{
		SleepForSecondsCommand(2), // wait to ensure runner has started
		containerFactory.NewContainer(cn, "setuidgid 1000:1111 cat /dev/"+cn, WithStartAndStop()),
	}

	RunTestSteps(testSteps, t)

	// Close the runner without calling Wait()
	assert.NoError(t, runner.Close())
	finishWG.Wait()

	expectedJsonMembers := map[string]any{
		"comm":  "cat",
		"fname": "/dev/" + cn,
		"uid":   1000.,
		"gid":   1111.,
		"flags": 0.,
		"mode":  0.,
		"ret":   -2.,
	}

	CheckEvents(t, events, expectedJsonMembers)
}
