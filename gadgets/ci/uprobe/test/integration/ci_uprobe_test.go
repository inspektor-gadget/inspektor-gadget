// Copyright 2026 The Inspektor Gadget authors
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

package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type goUprobeEvent struct {
	Proc    utils.Process `json:"proc"`
	Variant string        `json:"variant"`
	Name    string        `json:"name"`
}

// workloadImage is built locally by "make -C gadgets ci/uprobe/workload-image".
const workloadImage = "ig-ci-uprobe:test"

// Please keep the Go versions and build modes in sync with:
// - ../../workload/Dockerfile
// - ../../program.bpf.c
var (
	goVersions = []string{"1.25", "1.26"}
	buildModes = []string{"normal", "pie", "linker", "strip"}
)

func TestCiUprobe(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	// The workload image is built locally and is not pushed anywhere, so
	// it is only available to the local Docker daemon. What is tested here
	// (resolving Go symbols in the target binaries) does not depend on the
	// container runtime.
	if utils.Runtime != eventtypes.RuntimeNameDocker.String() {
		t.Skip("ci/uprobe test only supports the docker runtime (locally built workload image)")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")

	containerName := "test-ci-uprobe"
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(workloadImage),
		containers.WithoutContainerImagePull(),
	}

	commands := make([]string, 0, len(goVersions)*len(buildModes))
	expectedEntries := make([]*goUprobeEvent, 0, len(goVersions)*len(buildModes))
	for _, version := range goVersions {
		for _, mode := range buildModes {
			path := fmt.Sprintf("/opt/ig-tests/ci-uprobe/go%s/%s/target", version, mode)
			variant := fmt.Sprintf("GO%s_%s",
				strings.ReplaceAll(version, ".", ""), strings.ToUpper(mode))

			// The path is passed as an argument so that the gadget
			// reads it from the traced Go function instead of
			// relying on os.Args[0].
			commands = append(commands, path+" "+path)
			expectedEntries = append(expectedEntries, &goUprobeEvent{
				Proc:    utils.BuildProc("target", 0, 0),
				Variant: variant,
				Name:    path,
			})
		}
	}

	workload := containerFactory.NewContainer(
		containerName,
		strings.Join(commands, ";"),
		containerOpts...,
	)

	runnerOpts := []igrunner.Option{
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			normalize := func(event *goUprobeEvent) {
				utils.NormalizeProc(&event.Proc)
			}
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		}),
	}

	gadgetCmd := igrunner.New("ci/uprobe", runnerOpts...)
	steps := []igtesting.TestStep{gadgetCmd, workload}
	igtesting.RunTestSteps(steps, t)
}
