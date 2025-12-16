// Copyright 2022-2024 The Inspektor Gadget authors
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
	"fmt"
	"strings"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestFilterByContainerName(t *testing.T) {
	t.Parallel()

	cn := "test-filtered-container"
	listContainersCmd := &Command{
		Name: "RunFilterByContainerName",
		Cmd:  fmt.Sprintf("./ig list-containers -o json --runtimes=%s --containername=%s", *runtime, cn),
		ValidateOutput: func(t *testing.T, output string) {
			expectedContainer := &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						RuntimeName:   types.String2RuntimeName(*runtime),
						ContainerName: cn,
					},
				},
			}

			normalize := func(c *containercollection.Container) {
				c.OciConfig = ""
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""

				c.K8s.PodLabels = nil
				c.K8s.PodUID = ""
				c.Runtime.ContainerID = ""
				c.Runtime.ContainerPID = 0
				c.Runtime.ContainerStartedAt = 0
				// TODO: Handle once we support getting ContainerImageName from Docker
				c.Runtime.ContainerImageName = ""
				c.Runtime.ContainerImageDigest = ""
				c.Runtime.ContainerImageID = ""
			}

			match.MatchAllEntries(t, match.JSONSingleArrayMode, output, normalize, expectedContainer)
		},
	}

	testSteps := []TestStep{
		containerFactory.NewContainer(cn, "sleep inf", containers.WithStartAndStop()),
		SleepForSecondsCommand(2),
		listContainersCmd,
	}

	RunTestSteps(testSteps, t)
}

func TestWatchContainers(t *testing.T) {
	t.Parallel()

	cn := "test-watched-container"
	watchContainersCommand := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("./ig list-containers -o json --watch --runtimes=%s -c %s", *runtime, cn),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEvents := []*containercollection.PubSubEvent{
				{
					Type: containercollection.EventTypeAddContainer,
					Container: &containercollection.Container{
						Runtime: containercollection.RuntimeMetadata{
							BasicRuntimeMetadata: types.BasicRuntimeMetadata{
								RuntimeName:   types.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
				},
				{
					Type: containercollection.EventTypeRemoveContainer,
					Container: &containercollection.Container{
						Runtime: containercollection.RuntimeMetadata{
							BasicRuntimeMetadata: types.BasicRuntimeMetadata{
								RuntimeName:   types.String2RuntimeName(*runtime),
								ContainerName: cn,
							},
						},
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.OciConfig = ""
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Timestamp = ""

				e.Container.K8s.PodLabels = nil
				e.Container.K8s.PodUID = ""
				e.Container.Runtime.ContainerID = ""
				e.Container.Runtime.ContainerPID = 0
				e.Container.Runtime.ContainerStartedAt = 0
				// TODO: Handle once we support getting ContainerImageName from Docker
				e.Container.Runtime.ContainerImageName = ""
				e.Container.Runtime.ContainerImageDigest = ""
				e.Container.Runtime.ContainerImageID = ""
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEvents...)
		},
	}

	testSteps := []TestStep{
		watchContainersCommand,
		SleepForSecondsCommand(2),
		containerFactory.NewContainer(cn, "echo I am short lived container"),
	}

	RunTestSteps(testSteps, t)
}

func TestFilterByContainerImageDigest(t *testing.T) {
	t.Parallel()

	cn := "test-filter-digest"

	// Start container
	c := containerFactory.NewContainer(cn, "sleep inf", containers.WithStartAndStop())
	c.Start(t)
	defer c.Stop(t)

	// Wait a bit for container to be ready
	SleepForSecondsCommand(2).Run(t)

	var digest string

	// Get digest
	getDigestCmd := &Command{
		Name: "GetDigest",
		Cmd:  fmt.Sprintf("./ig list-containers -o json --runtimes=%s --containername=%s", *runtime, cn),
		ValidateOutput: func(t *testing.T, output string) {
			var containers []*containercollection.Container
			err := json.Unmarshal([]byte(output), &containers)
			if err != nil {
				t.Fatalf("failed to unmarshal json: %v", err)
			}
			if len(containers) == 0 {
				t.Fatalf("no containers found")
			}
			digest = containers[0].Runtime.ContainerImageDigest
			if digest == "" {
				t.Fatalf("container image digest is empty")
			}
			t.Logf("Got digest: %s", digest)
		},
	}
	getDigestCmd.Run(t)

	// Helper to run filter test
	runFilterTest := func(name, filterValue string, shouldMatch bool) {
		cmd := &Command{
			Name: name,
			Cmd:  fmt.Sprintf("./ig list-containers -o json --runtimes=%s --runtime-containerimage-digest=%s", *runtime, filterValue),
			ValidateOutput: func(t *testing.T, output string) {
				var containers []*containercollection.Container
				err := json.Unmarshal([]byte(output), &containers)
				if err != nil {
					t.Fatalf("failed to unmarshal json: %v", err)
				}

				found := false
				for _, c := range containers {
					if c.Runtime.ContainerName == cn {
						found = true
						break
					}
				}

				if shouldMatch {
					if !found {
						t.Fatalf("container %s not found in output matching filter %s", cn, filterValue)
					}
				} else {
					if found {
						t.Fatalf("container %s SHOULD NOT be found in output matching filter %s", cn, filterValue)
					}
				}
			},
		}
		cmd.Run(t)
	}

	// 1. Full digest
	runFilterTest("FilterByFullDigest", digest, true)

	// 2. Truncated digest (12 chars)
	// Remove prefix if present for truncation logic (although the filter handles it, we want to pass 12 chars of the hash)
	hash := digest
	if idx := strings.Index(hash, ":"); idx != -1 {
		hash = hash[idx+1:]
	}
	if len(hash) > 12 {
		truncated := hash[:12]
		runFilterTest("FilterByTruncatedDigest", truncated, true)
	}

	// 3. Digest without prefix (if present)
	if strings.Contains(digest, ":") {
		runFilterTest("FilterByDigestNoPrefix", hash, true)
	}

	// 4. Wrong digest
	runFilterTest("FilterByWrongDigest", "sha256:0000000000000000000000000000000000000000000000000000000000000000", false)
}
