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
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/profile"
	bioTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/tracer"
)

func newBlockIOCmd() *cobra.Command {
	var profileFlags ProfileFlags

	runCmd := func(*cobra.Command, []string) error {
		if profileFlags.Containername != "" || profileFlags.Runtimes != strings.Join(containerutils.AvailableRuntimes, ",") {
			return fmt.Errorf("block-io gadget doesn't support filtering")
		}

		blockIOGadget := &ProfileGadget{
			profileFlags:  &profileFlags,
			inProgressMsg: "Tracing block device I/O",
			parser: &commonprofile.BlockIOParser{
				OutputConfig: profileFlags.OutputConfig,
			},
			createAndRunTracer: func() (profile.Tracer, error) {
				return bioTracer.NewTracer()
			},
		}

		return blockIOGadget.Run()
	}

	cmd := commonprofile.NewBlockIOCmd(runCmd)
	AddCommonProfileFlags(cmd, &profileFlags)

	return cmd
}
