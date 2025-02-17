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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

const (
	adviseDsName  = "advise"
	containerName = "mycontainer"
)

type SeccompProfile struct {
	DefaultAction string     `json:"defaultAction"`
	Architectures []string   `json:"architectures"`
	Syscalls      []Syscalls `json:"syscalls"`
}

type Syscalls struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	validate       func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]SeccompProfile)
}

func TestAdviseSeccompGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	// see https://github.com/inspektor-gadget/inspektor-gadget/issues/3751
	gadgettesting.MinimumKernelVersion(t, "5.6")

	testCases := map[string]testDef{
		"all_containers": {
			runnerConfig: &utilstest.RunnerConfig{},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]SeccompProfile) {
				require.GreaterOrEqual(t, len(policies), 1)
			},
		},
		"specific_container": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, policies map[string]SeccompProfile) {
				policy, ok := policies[containerName]
				require.True(t, ok)

				require.Len(t, policy.Syscalls, 1)
				syscalls := policy.Syscalls[0]

				require.Contains(t, syscalls.Names, "getpid")
				require.Contains(t, syscalls.Names, "getppid")
				require.Contains(t, syscalls.Names, "getuid")
				require.Contains(t, syscalls.Names, "geteuid")
				require.Contains(t, syscalls.Names, "openat")
				require.Contains(t, syscalls.Names, "close")
				require.Contains(t, syscalls.Names, "sysinfo")
				require.Contains(t, syscalls.Names, "chdir")
				require.Contains(t, syscalls.Names, "mmap")
				require.Contains(t, syscalls.Names, "munmap")

				// check syscalls that should not be present
				require.NotContains(t, syscalls.Names, "unshare")
				require.NotContains(t, syscalls.Names, "mkdir")
				require.NotContains(t, syscalls.Names, "reboot")
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

			policies := make(map[string]SeccompProfile)

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			// this gadget requires the runtime.containerName to be present, add
			// a simple operator to set it only for the runner that generates
			// the events
			myOp := simple.New("myop",
				simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
					syscallsDs := gadgetCtx.GetDataSources()["syscalls"]
					require.NotNil(t, syscallsDs)

					runtimeContainerNameF, err := syscallsDs.AddField("runtime.containerName", api.Kind_String)
					require.NoError(t, err)

					k8sContainerNameF, err := syscallsDs.AddField("k8s.containerName", api.Kind_String)
					require.NoError(t, err)

					syscallsDs.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
						mntnsidF := ds.GetField("mntns_id_raw")
						require.NotNil(t, mntnsidF)

						mntnsid, err := mntnsidF.Uint64(data)
						require.NoError(t, err)

						if mntnsid != runner.Info.MountNsID {
							return nil
						}

						err = runtimeContainerNameF.PutString(data, containerName)
						require.NoError(t, err)
						k8sContainerNameF.PutString(data, containerName)
						require.NoError(t, err)

						return nil
					}, 100)

					return nil
				}),
			)

			gadgetRunner.DataOperator = append(gadgetRunner.DataOperator, myOp)
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

				var policy SeccompProfile
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
// Geteuid, Open, Close, Sysinfo, Chdir, Getcwd, Mmap and Munmap.
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
