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

package image

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func NewInspectCmd(runtime runtime.Runtime) *cobra.Command {
	var outputMode string

	outputModes := []string{utils.OutputModeYAML, utils.OutputModeJSON, utils.OutputModeJSONPretty, utils.OutputModeCustom}

	cmd := &cobra.Command{
		Use:          "inspect",
		Short:        "Inspect the local gadget image",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
	}

	cmd.PersistentFlags().String("extra-info", "", "Custom info type to display")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		image, err := oci.GetGadgetImageDesc(context.TODO(), args[0])
		if err != nil {
			return fmt.Errorf("inspecting image: %w", err)
		}

		runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
		runtimeParams := runtime.ParamDescs().ToParams()
		ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()
		ociParams.Set("pull", oci.PullImageNever)

		// Add operator global flags
		opGlobalParams := make(map[string]*params.Params)
		for _, op := range operators.GetDataOperators() {
			opGlobalParams[op.Name()] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
		}
		if ociParams, exists := opGlobalParams["oci"]; exists {
			ociParams.Set("verify-image", "false")
		}

		var info *api.GadgetInfo
		err = runtime.Init(runtimeGlobalParams)
		if err != nil {
			return fmt.Errorf("initializing runtime: %w", err)
		}
		defer runtime.Close()

		// set global operator flags from the config file
		for o, p := range opGlobalParams {
			err = common.SetFlagsForParams(cmd, p, config.OperatorKey+"."+o)
			if err != nil {
				return fmt.Errorf("setting operator %s flags: %w", o, err)
			}
		}

		ops := make([]operators.DataOperator, 0)
		for _, op := range operators.GetDataOperators() {
			// Initialize operator
			err := op.Init(opGlobalParams[op.Name()])
			if err != nil {
				continue
			}
			ops = append(ops, op)
		}

		gadgetCtx := gadgetcontext.New(
			context.Background(),
			image.String(),
			gadgetcontext.WithDataOperators(ops...),
			gadgetcontext.WithUseInstance(false),
			gadgetcontext.IncludeExtraInfo(true),
		)

		paramValueMap := make(map[string]string)
		ociParams.CopyToMap(paramValueMap, "operator.oci.")

		info, err = runtime.GetGadgetInfo(gadgetCtx, runtimeParams, paramValueMap)
		if err != nil {
			return fmt.Errorf("getting gadget info: %w", err)
		}

		extraInfoMap := make(map[string]interface{})
		for k, v := range info.ExtraInfo.Data {
			extraInfoMap[k] = map[string]string{
				"contentType": string(v.ContentType),
				"content":     string(v.Content),
			}
		}
		switch outputMode {
		case utils.OutputModeJSON:
			bytes, err := json.Marshal(extraInfoMap)
			if err != nil {
				return fmt.Errorf("marshalling image and extra info to JSON: %w", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(bytes))
		case utils.OutputModeJSONPretty:
			bytes, err := json.MarshalIndent(extraInfoMap, "", "  ")
			if err != nil {
				return fmt.Errorf("marshalling image and extra info to JSON: %w", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(bytes))
		case utils.OutputModeYAML:
			bytes, err := yaml.Marshal(extraInfoMap)
			if err != nil {
				return fmt.Errorf("marshalling image and extra info to YAML: %w", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(bytes))
		case utils.OutputModeCustom:
			extraInfo, _ := cmd.PersistentFlags().GetString("extra-info")
			if extraInfo == "" {
				return fmt.Errorf("extra info not specified (see --extra-info)")
			}
			if info.ExtraInfo.Data[extraInfo] == nil {
				return fmt.Errorf("extra info %q not found", extraInfo)
			}
			customInfo := string(info.ExtraInfo.Data[extraInfo].Content)
			fmt.Fprint(cmd.OutOrStdout(), customInfo)
		default:
			return fmt.Errorf("invalid output mode %q, valid values are: %s", outputMode, strings.Join(outputModes, ", "))
		}
		return nil
	}

	cmd.Flags().StringVarP(
		&outputMode,
		"output",
		"o",
		utils.OutputModeJSONPretty,
		fmt.Sprintf("Output mode, possible values are, %s", strings.Join(outputModes, ", ")),
	)

	return cmd
}
