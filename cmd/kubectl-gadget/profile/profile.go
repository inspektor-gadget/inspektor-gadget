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
	"os"
	"os/signal"
	"time"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/spf13/cobra"
)

// ProfileParser defines the interface that every profile-gadget parser has to
// implement.
type ProfileParser interface {
	DisplayResultsCallback(string, []string) error
}

// ProfileGadget represents a gadget belonging to the profile category.
type ProfileGadget struct {
	gadgetName    string
	commonFlags   *utils.CommonFlags
	params        map[string]string
	inProgressMsg string
	parser        ProfileParser
}

// Run runs a ProfileGadget and prints the output after parsing it using the
// ProfileParser's methods.
func (g *ProfileGadget) Run() error {
	traceConfig := &utils.TraceConfig{
		GadgetName:        g.gadgetName,
		Operation:         gadgetv1alpha1.OperationStart,
		TraceOutputMode:   gadgetv1alpha1.TraceOutputModeStatus,
		TraceOutputState:  gadgetv1alpha1.TraceStateCompleted,
		TraceInitialState: gadgetv1alpha1.TraceStateStarted,
		Parameters:        g.params,
		CommonFlags:       g.commonFlags,
	}

	traceID, err := utils.CreateTrace(traceConfig)
	if err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}
	defer utils.DeleteTrace(traceID)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	if g.commonFlags.Timeout != 0 {
		go func() {
			time.Sleep(time.Duration(g.commonFlags.Timeout) * time.Second)
			c <- os.Interrupt
		}()
	}

	if g.commonFlags.OutputMode != commonutils.OutputModeJSON {
		if g.commonFlags.Timeout != 0 {
			fmt.Printf(g.inProgressMsg + "...")
		} else {
			fmt.Printf("%s... Hit Ctrl-C to end.", g.inProgressMsg)
		}
	}

	<-c

	if g.commonFlags.OutputMode != commonutils.OutputModeJSON {
		// Trick to have ^C on the same line than above message, so the gadget
		// output begins on a "clean" line.
		fmt.Println()
	}

	err = utils.SetTraceOperation(traceID, string(gadgetv1alpha1.OperationStop))
	if err != nil {
		return commonutils.WrapInErrStopGadget(err)
	}

	err = utils.PrintTraceOutputFromStatus(traceID,
		string(traceConfig.TraceOutputState), g.parser.DisplayResultsCallback)
	if err != nil {
		return commonutils.WrapInErrGetGadgetOutput(err)
	}

	return nil
}

func NewProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Profile different subsystems",
	}

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newCPUCmd())

	return cmd
}
