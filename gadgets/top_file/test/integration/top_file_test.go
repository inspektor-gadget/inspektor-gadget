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

type topFileEntry struct {
	eventtypes.CommonData

	MntNsID uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	Reads      uint64 `json:"reads"`
	Writes     uint64 `json:"writes"`
	ReadBytes  uint64 `json:"rbytes"`
	WriteBytes uint64 `json:"wbytes"`

	FileType  string `json:"t"`
	FileName  string `json:"file"`
	FileInode uint64 `json:"inode"`
	FileDev   uint64 `json:"dev"`
}

func TestTopFile(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-top-file"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-top-file")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do echo -n foo > bar ; sleep 1; done",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(containerImage),
		utils.WithContainerID(testContainer.ID()),
	}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-r=%s", utils.Runtime),
				fmt.Sprintf("-c=%s", containerName),
			),
		)
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &topFileEntry{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),

					// Workload writes "foo" with "echo" (so "sh") command into
					// a regular file ('R') named "bar" once per second. The
					// gadget runs every second, so we expect 1 write operation
					// with 3 bytes.
					Comm:       "sh",
					FileType:   "R",
					FileName:   "/bar",
					Writes:     1,
					WriteBytes: 3,

					// Nothing is read
					Reads:     0,
					ReadBytes: 0,

					// Check the existence of the following fields
					MntNsID:   utils.NormalizedInt,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					FileInode: utils.NormalizedInt,

					// Manually normalize fields that might contain 0, so we
					// can't use NormalizedInt and NormalizeInt()
					// TODO: Support checking for the presence of a field, even if it's 0
					Uid:     0,
					Gid:     0,
					FileDev: 0,
				}

				normalize := func(e *topFileEntry) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeInt(&e.MntNsID)
					utils.NormalizeInt(&e.Pid)
					utils.NormalizeInt(&e.Tid)
					utils.NormalizeInt(&e.FileInode)

					// Manually normalize fields that might contain 0
					e.Uid = 0
					e.Gid = 0
					e.FileDev = 0
				}

				match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	topFileCmd := igrunner.New("top_file", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{topFileCmd}, t, testingOpts...)
}
