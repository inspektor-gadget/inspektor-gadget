// Copyright 2019-2022 The Inspektor Gadget authors
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

	"github.com/spf13/cobra"

	commonprofile "github.com/inspektor-gadget/inspektor-gadget/cmd/common/profile"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/profile"
)

type ProfileFlags struct {
	utils.CommonFlags
}

// ProfileGadget represents a gadget belonging to the profile category.
type ProfileGadget struct {
	profileFlags  *ProfileFlags
	inProgressMsg string
	parser        commonprofile.ProfileParser

	createAndRunTracer func() (profile.Tracer, error)
}

// Run runs a ProfileGadget and prints the output after parsing it using the
// ProfileParser's methods.
func (g *ProfileGadget) Run() error {
	gadgetTracer, err := g.createAndRunTracer()
	if err != nil {
		return commonutils.WrapInErrGadgetTracerCreateAndRun(err)
	}

	if g.profileFlags.OutputMode != commonutils.OutputModeJSON {
		if g.profileFlags.Timeout != 0 {
			fmt.Printf(g.inProgressMsg + "...")
		} else {
			fmt.Printf("%s... Hit Ctrl-C to end.", g.inProgressMsg)
		}
	}

	utils.WaitForEnd(&g.profileFlags.CommonFlags)

	result, err := gadgetTracer.Stop()
	if err != nil {
		return err
	}

	// Trick to have ^C on the same line than above message, so the gadget
	// output begins on a "clean" line.
	fmt.Println()

	err = g.parser.DisplayResultsCallback("", []string{result})
	if err != nil {
		return err
	}

	return nil
}

func AddCommonProfileFlags(command *cobra.Command, profileFlags *ProfileFlags) {
	utils.AddCommonFlags(command, &profileFlags.CommonFlags)
}

func NewProfileCmd() *cobra.Command {
	cmd := commonprofile.NewCommonProfileCmd()

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newCPUCmd())

	return cmd
}
