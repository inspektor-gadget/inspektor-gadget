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
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runner"
)

func DrainEvents(t *testing.T, r *runner.Runner, events *[]string, finishWG *sync.WaitGroup) {
	for !r.Done() {
		event, err := r.GetEvent()
		assert.NoError(t, err)
		*events = append(*events, event)
	}
	if finishWG != nil {
		finishWG.Done()
	}
}

func RunAndGetEvents(t *testing.T, image string, events *[]string, finishWG *sync.WaitGroup, opts ...func(*runner.RunnerOpts)) {
	gadgetRunner, err := runner.NewRunner(image,
		runner.WithContext(context.Background()),
		runner.WithTimeout(10*time.Second),
		runner.WithPullPolicy(oci.PullImageNever),
	)
	require.NoError(t, err)
	require.NotNil(t, gadgetRunner)

	require.NoError(t, gadgetRunner.Run())
	defer gadgetRunner.Close()

	DrainEvents(t, gadgetRunner, events, nil)
	assert.NoError(t, gadgetRunner.Wait())
	assert.NoError(t, gadgetRunner.Close())

	finishWG.Done()
}

func CheckEvents(t *testing.T, events []string, expectedJsonMembers map[string]any) {
out:
	for _, event := range events {
		jsonMap := make(map[string]any)
		err := json.Unmarshal([]byte(event), &jsonMap)
		require.NoError(t, err, "Unmarshalling event should succeed")

		for k, v := range expectedJsonMembers {
			if v != jsonMap[k] {
				continue out
			}
		}
		return
	}
	assert.Fail(t, "Expected event not found")

	fmt.Printf("Captured events:{\n")
	for _, event := range events {
		fmt.Printf("\t%s\n", event)
	}
	fmt.Printf("}\n")
	fmt.Printf("Expected event: %s\n", expectedJsonMembers)
}

func TestRunner(t *testing.T) {
	t.Parallel()
	cn := "test-runner"

	// Pull image before running the test
	image := "ghcr.io/inspektor-gadget/gadget/trace_open"
	_, err := oci.PullGadgetImage(context.Background(), image, &oci.AuthOptions{AuthFile: oci.DefaultAuthFile})
	require.NoError(t, err, "Pulling the gadget image should succeed")

	var events []string
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	go RunAndGetEvents(t, image, &events, finishWG)

	testSteps := []TestStep{
		SleepForSecondsCommand(2), // wait to ensure runner has started
		containerFactory.NewContainer(cn, "setuidgid 1000:1111 cat /dev/"+cn, WithStartAndStop()),
	}

	RunTestSteps(testSteps, t)
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
