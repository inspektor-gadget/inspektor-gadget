// Copyright 2022 The Inspektor Gadget authors
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

package profile

import (
	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/profile"
	cpuTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/tracer"
	cpuTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

func newCPUCmd() *cobra.Command {
	var profileFlags ProfileFlags
	var cpuFlags commonprofile.CPUFlags

	runCmd := func(*cobra.Command, []string) error {
		if cpuFlags.ProfileUserOnly && cpuFlags.ProfileKernelOnly {
			return commonutils.WrapInErrArgsNotSupported("-U and -K can't be used at the same time")
		}

		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&profileFlags.OutputConfig, cpuTypes.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		localGadgetManager, err := localgadgetmanager.NewManager(profileFlags.RuntimeConfigs)
		if err != nil {
			return commonutils.WrapInErrManagerInit(err)
		}
		defer localGadgetManager.Close()

		// TODO: Improve filtering, see further details in
		// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
		containerSelector := containercollection.ContainerSelector{
			Name: profileFlags.Containername,
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := localGadgetManager.CreateMountNsMap(containerSelector)
		if err != nil {
			return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}
		defer localGadgetManager.RemoveMountNsMap()

		cpuGadget := &ProfileGadget{
			profileFlags: &profileFlags,
			parser: &commonprofile.CPUParser{
				GadgetParser: *parser,
				OutputConfig: profileFlags.OutputConfig,
				CPUFlags:     &cpuFlags,
			},
			inProgressMsg: "Capturing stack traces",
			createAndRunTracer: func() (profile.Tracer, error) {
				return cpuTracer.NewTracer(&localGadgetManager.ContainerCollection, &cpuTracer.Config{
					MountnsMap:      mountnsmap,
					UserStackOnly:   cpuFlags.ProfileUserOnly,
					KernelStackOnly: cpuFlags.ProfileKernelOnly,
				})
			},
		}

		return cpuGadget.Run()
	}

	cmd := commonprofile.NewCPUCmd(runCmd, &cpuFlags)
	AddCommonProfileFlags(cmd, &profileFlags)

	return cmd
}
