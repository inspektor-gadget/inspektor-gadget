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
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

const adviseDsName = "advise"

type seccompPolicy struct {
	DefaultAction string   `json:"defaultAction"`
	Architectures []string `json:"architectures"`
	Syscalls      []string `json:"syscalls"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	validate       func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]seccompPolicy)
}

func TestAdviseSeccompGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	// see https://github.com/inspektor-gadget/inspektor-gadget/issues/3751
	gadgettesting.MinimumKernelVersion(t, "5.6")

	testCases := map[string]testDef{
		"all_containers": {
			runnerConfig: &utilstest.RunnerConfig{},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]seccompPolicy) {
				require.GreaterOrEqual(t, len(policies), 1)
			},
		},
		"filtering_no_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, 0)
			},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]seccompPolicy) {
				require.Len(t, policies, 0)
			},
		},
		"filtering_exact_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]seccompPolicy) {
				policy, ok := policies[fmt.Sprintf("mntnsid %d", info.MountNsID)]
				require.True(t, ok)
				require.Contains(t, policy.Syscalls, "getpid")
				require.Contains(t, policy.Syscalls, "getppid")
				require.Contains(t, policy.Syscalls, "getuid")
				require.Contains(t, policy.Syscalls, "geteuid")
				require.Contains(t, policy.Syscalls, "openat")
				require.Contains(t, policy.Syscalls, "close")
				require.Contains(t, policy.Syscalls, "sysinfo")
				require.Contains(t, policy.Syscalls, "chdir")
				require.Contains(t, policy.Syscalls, "mmap")
				require.Contains(t, policy.Syscalls, "munmap")
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, executeSyscalls)
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[any]{
				Image:          "advise_seccomp",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
				ParamValues: map[string]string{
					"operator.oci.ebpf.map-fetch-count":    "0",
					"operator.oci.ebpf.map-fetch-interval": "0",
				},
			}

			policies := make(map[string]seccompPolicy)

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.DataFunc = func(ds datasource.DataSource, data datasource.Data) error {
				if ds.Name() != adviseDsName {
					return nil
				}

				textField := ds.GetField("text")
				require.NotNil(t, textField)

				text, err := textField.String(data)
				require.NoError(t, err)

				subparts := strings.SplitN(text, "\n", 2)
				require.Len(t, subparts, 2)

				name := strings.TrimPrefix(subparts[0], `// `)
				content := subparts[1]

				var policy seccompPolicy
				err = json.Unmarshal([]byte(content), &policy)
				require.NoError(t, err)

				policies[name] = policy

				return nil
			}

			gadgetRunner.RunGadget()

			testCase.validate(t, runner.Info, policies)
		})
	}
}

// executeSyscalls executes the following syscalls: Getpid, Getppid, Getuid,
// Geteuid, Open, Close, Sysinfo, Chdir, Getcwd,Mmap and Munmap.
func executeSyscalls() error {
	syscall.Getpid()
	syscall.Getppid()
	syscall.Getuid()
	syscall.Geteuid()

	fd, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0o644)
	if err == nil {
		syscall.Close(fd)
	}

	var info syscall.Sysinfo_t
	syscall.Sysinfo(&info)

	if err := syscall.Chdir("/"); err == nil {
		cwd := make([]byte, 256)
		syscall.Getcwd(cwd)
	}

	mem, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err == nil {
		syscall.Munmap(mem)
	}

	return nil
}
