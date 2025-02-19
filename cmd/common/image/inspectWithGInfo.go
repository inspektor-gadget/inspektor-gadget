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

package image

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends/console"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const specialAnnotation = "inspect-gadget=true"

func NewInspectWithGInfoCmd(runtime runtime.Runtime) *cobra.Command {
	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
	runtimeParams := runtime.ParamDescs().ToParams()

	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()

	// Add operator global flags
	opGlobalParams := make(map[string]*params.Params)
	for _, op := range operators.GetDataOperators() {
		opGlobalParams[op.Name()] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}

	run := func(cmd *cobra.Command, args []string) error {
		showHelp, _ := cmd.Flags().GetBool("help")
		if showHelp {
			return cmd.Help()
		}

		fe := console.NewFrontend()
		defer fe.Close()

		ctx := fe.GetContext()

		ops := make([]operators.DataOperator, 0)
		for _, op := range operators.GetDataOperators() {
			err := op.Init(opGlobalParams[op.Name()])
			if err != nil {
				log.Warnf("error initializing operator %s: %v", op.Name(), err)
				continue
			}
			ops = append(ops, op)
		}

		gadgetCtx := gadgetcontext.New(
			ctx,
			args[0],
			gadgetcontext.WithDataOperators(ops...),
		)

		paramValueMap := make(map[string]string)
		ociParams.CopyToMap(paramValueMap, "operator.oci.")

		// Request gadget info with extra information (verbose)
		ginfo, err := runtime.GetGadgetInfo(gadgetCtx, runtimeParams, paramValueMap, true)
		if err != nil {
			return err
		}

		fmt.Printf("Gadget extra info: %v\n", ginfo.GetExtraInfo())

		return nil
	}

	cmd := &cobra.Command{
		// TODO: this all should be parameters
		Use:          "inspectWithGInfo",
		Short:        "TODO THIS AND THAT",
		SilenceUsage: true, // do not print usage when there is an error
		RunE:         run,
		Args:         cobra.ExactArgs(1),
	}

	common.AddOCIFlags(cmd, runtimeGlobalParams, nil, runtime)
	common.AddOCIFlags(cmd, runtimeParams, nil, runtime)

	for _, operatorParams := range opGlobalParams {
		common.AddOCIFlags(cmd, operatorParams, nil, runtime)
	}

	return cmd
}
