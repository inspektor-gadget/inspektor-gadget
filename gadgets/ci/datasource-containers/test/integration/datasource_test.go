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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type DatasourceContainersEvent struct {
	ContainerID     string `json:"container_id"`
	ContainerConfig string `json:"container_config"`
	CgroupID        uint64 `json:"cgroup_id"`
	EventType       string `json:"event_type"`
	MntnsID         uint64 `json:"mntns_id"`
	Name            string `json:"name"`
}

func TestDatasourceContainers(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-datasource-containers"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-datasource-containers")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"sleep inf",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime)))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &DatasourceContainersEvent{
				EventType:       "CREATED",
				Name:            containerName,
				MntnsID:         utils.NormalizedInt,
				CgroupID:        utils.NormalizedInt,
				ContainerID:     utils.NormalizedStr,
				ContainerConfig: utils.NormalizedStr,
			}

			normalize := func(e *DatasourceContainersEvent) {
				utils.NormalizeInt(&e.CgroupID)
				utils.NormalizeInt(&e.MntnsID)
				utils.NormalizeString(&e.ContainerID)

				// only validate the OCI config is not empty before normalizing it
				var spec *ocispec.Spec
				err = json.Unmarshal([]byte(e.ContainerConfig), &spec)
				require.NoError(t, err, "unmarshalling OCI config")
				require.NotNil(t, spec, "OCI spec is not empty")
				require.NotEmpty(t, spec.Version, "OCI runtime spec version is not empty")
				utils.NormalizeString(&e.ContainerConfig)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	runnerOpts = append(runnerOpts, igrunner.WithStartAndStop())
	datasourceContainersCmd := igrunner.New("ci/datasource-containers", runnerOpts...)

	steps := []igtesting.TestStep{
		datasourceContainersCmd,
		// wait to ensure ig or kubectl-gadget has started
		utils.Sleep(3 * time.Second),
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
