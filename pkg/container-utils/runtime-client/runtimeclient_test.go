// Copyright 2023 The Inspektor Gadget authors
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

package runtimeclient_test

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	containerNamePrefix = "test-container"
	// untagged/undigested image name
	baseImageName = "docker.io/library/alpine"
	numContainers = 2
)

func containerImageDigest(t *testing.T) string {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return "sha256:16edc9559472f368b71e0f19a575e71080f2251f6693e7d560e21cc6472f7da6"
	case "arm64":
		return "sha256:e31c3b1cd47718260e1b6163af0a05b3c428dc01fa410baf72ca8b8076e22e72"
	default:
		t.Fatalf("arch %q: %v", runtime.GOARCH, errors.ErrUnsupported)
	}
	return ""
}

func containerImageName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s@%s", baseImageName, containerImageDigest(t))
}

// TODO: make containerImageName consistent between container runtimes.
// https://github.com/inspektor-gadget/inspektor-gadget/pull/2798#discussion_r1598477792
func expectedContainerImageName(t *testing.T, runtime types.RuntimeName) string {
	t.Helper()
	switch runtime {
	case types.RuntimeNameDocker:
		return baseImageName
	case types.RuntimeNameContainerd:
		return containerImageName(t)
	default:
		return ""
	}
}

func TestRuntimeClientInterface(t *testing.T) {
	t.Parallel()
	utilstest.RequireRoot(t)

	for _, runtime := range testutils.SupportedContainerRuntimes {
		t.Run(runtime.String(), func(t *testing.T) {
			runtime := runtime
			t.Parallel()

			// Create test containers and their expected data
			var expectedData []*runtimeclient.ContainerDetailsData
			for i := 0; i < numContainers; i++ {
				cn := fmt.Sprintf("%s-%s-%d", containerNamePrefix, runtime, i)
				c, err := testutils.NewContainer(
					runtime,
					cn,
					"sleep inf", // We simply want to keep the container running
					testutils.WithImage(containerImageName(t)),
				)
				require.Nil(t, err)
				require.NotNil(t, c)

				c.Start(t)
				t.Cleanup(func() {
					c.Stop(t)
				})

				expectedData = append(expectedData,
					&runtimeclient.ContainerDetailsData{
						ContainerData: runtimeclient.ContainerData{
							Runtime: runtimeclient.RuntimeContainerData{
								BasicRuntimeMetadata: types.BasicRuntimeMetadata{
									RuntimeName:          runtime,
									ContainerName:        cn,
									ContainerID:          c.ID(),
									ContainerImageName:   expectedContainerImageName(t, runtime),
									ContainerImageDigest: containerImageDigest(t),
								},
								State: runtimeclient.StateRunning,
							},
							K8s: runtimeclient.K8sContainerData{},
						},
						Pid: c.Pid(),
						// TODO: Is it worth to compare the cgroups path and mounts?
					},
				)
			}

			// Initialize runtime client
			config := &containerutilsTypes.RuntimeConfig{
				Name: runtime,
			}
			rc, err := containerutils.NewContainerRuntimeClient(config)
			t.Cleanup(func() {
				if rc != nil {
					rc.Close()
				}
			})
			require.Nil(t, err)
			require.NotNil(t, rc)

			// Test runtime client methods
			t.Run("GetContainers", func(t *testing.T) {
				t.Parallel()

				containers, err := rc.GetContainers()
				require.Nil(t, err)
				require.NotNil(t, containers)

				for _, eData := range expectedData {
					found := false
					for _, cData := range containers {
						if cmp.Equal(*cData, eData.ContainerData) {
							found = true
							break
						}
					}
					require.True(t, found, "couldn't find container:\n%s\nin:\n%s",
						spew.Sdump(eData.ContainerData), spew.Sdump(containers))
				}
			})

			t.Run("GetContainer", func(t *testing.T) {
				t.Parallel()

				for _, eData := range expectedData {
					cData, err := rc.GetContainer(eData.Runtime.ContainerID)
					require.Nil(t, err)
					require.NotNil(t, cData)
					require.True(t, cmp.Equal(*cData, eData.ContainerData),
						"unexpected container data:\n%s", cmp.Diff(*cData, eData.ContainerData))
				}
			})

			t.Run("GetContainerDetails", func(t *testing.T) {
				t.Parallel()

				for _, eData := range expectedData {
					cData, err := rc.GetContainerDetails(eData.Runtime.ContainerID)
					require.Nil(t, err)
					require.NotNil(t, cData)

					// TODO: Is it worth to compare the cgroups path and mounts?
					require.NotEmpty(t, cData.CgroupsPath)
					cData.CgroupsPath = eData.CgroupsPath
					cData.Mounts = eData.Mounts

					require.True(t, cmp.Equal(cData, eData),
						"unexpected container data:\n%s", cmp.Diff(cData, eData))
				}
			})
		})
	}
}

// TestDeleteContainers is useful to delete containers from
// TestRuntimeClientInterface that were not properly deleted because of a bug.
// func TestDeleteContainers(t *testing.T) {
// 	t.Parallel()
// 	utilstest.RequireRoot(t)

// 	for _, runtime := range testutils.SupportedContainerRuntimes {
// 		t.Run(runtime.String(), func(t *testing.T) {
// 			runtime := runtime
// 			t.Parallel()

// 			// Delete test containers from previous runs
// 			for i := 0; i < numContainers; i++ {
// 				cn := fmt.Sprintf("%s-%s-%d", containerNamePrefix, runtime, i)
// 				c, err := testutils.NewContainer(runtime, cn, "sleep inf", testutils.WithForceDelete())
// 				require.Nil(t, err)
// 				require.NotNil(t, c)
// 				c.Stop(t)
// 			}
// 		})
// 	}
// }
