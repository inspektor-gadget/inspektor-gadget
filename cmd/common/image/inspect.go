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

	"github.com/PaesslerAG/jsonpath"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func NewInspectCmd(runtime runtime.Runtime) *cobra.Command {
	var outputMode string

	opGlobalParams := make(map[string]*params.Params)

	outputModes := []string{utils.OutputModeYAML, utils.OutputModeJSON, utils.OutputModeJSONPretty}

	cmd := &cobra.Command{
		Use:          "inspect",
		Short:        "Inspect a gadget image",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
	}

	cmd.PersistentFlags().String("extra-info", "", "Custom info type to display")
	cmd.PersistentFlags().String("jsonpath", "", "JSONPath to extract from the extra info")

	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()

	for _, op := range operators.GetDataOperators() {
		opGlobalParams[op.Name()] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}

	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
	runtimeParams := runtime.ParamDescs().ToParams()

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		image := args[0]

		runtime.Init(runtimeGlobalParams)
		defer runtime.Close()

		// set global operator flags from the config file
		for o, p := range opGlobalParams {
			err := common.SetFlagsForParams(cmd, p, config.OperatorKey+"."+o)
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
			image,
			gadgetcontext.WithDataOperators(ops...),
			gadgetcontext.WithUseInstance(false),
			gadgetcontext.IncludeExtraInfo(true),
		)

		paramValueMap := make(map[string]string)
		ociParams.CopyToMap(paramValueMap, "operator.oci.")

		info, err := runtime.GetGadgetInfo(gadgetCtx, runtimeParams, paramValueMap)
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

		extraInfo, _ := cmd.PersistentFlags().GetString("extra-info")
		if extraInfo != "" {
			if _, ok := info.ExtraInfo.Data[extraInfo]; !ok {
				return fmt.Errorf("extra info %q not found", extraInfo)
			}

			jsonPath, _ := cmd.PersistentFlags().GetString("jsonpath")

			dataEntry := info.ExtraInfo.Data[extraInfo]
			customMap := make(map[string]interface{})
			if dataEntry.ContentType == "application/json" {
				// unmarshal the JSON content
				var dataEntryContent interface{}
				if err := json.Unmarshal(dataEntry.Content, &dataEntryContent); err != nil {
					return fmt.Errorf("unmarshalling JSON content: %w", err)
				}
				customMap[extraInfo] = dataEntryContent
			} else {
				customMap[extraInfo] = string(dataEntry.Content)
			}
			extraInfoMap = customMap
			if jsonPath != "" {
				// unmarshal the JSON content
				var dataEntryContent interface{}
				if err := json.Unmarshal(dataEntry.Content, &dataEntryContent); err != nil {
					return fmt.Errorf("unmarshalling JSON content: %w", err)
				}

				result, err := jsonpath.Get(fmt.Sprintf("$%s", jsonPath), dataEntryContent)
				if err != nil {
					return fmt.Errorf("resolving path %q: %w", jsonPath, err)
				}
				if result == nil {
					return fmt.Errorf("path %q not found in extra info %q", jsonPath, extraInfo)
				}

				// overwrite extrainfo map
				customMap := make(map[string]interface{})
				customMap[fmt.Sprintf("%s%s", extraInfo, jsonPath)] = result
				extraInfoMap = customMap
			}
		}

		switch outputMode {
		case utils.OutputModeJSON:
			bytes, err := json.Marshal(extraInfoMap)
			if err != nil {
				return fmt.Errorf("marshalling image and extra info to JSON: %w", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(bytes), "\n")
		case utils.OutputModeJSONPretty:
			bytes, err := json.MarshalIndent(extraInfoMap, "", "  ")
			if err != nil {
				return fmt.Errorf("marshalling image and extra info to JSON: %w", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(bytes), "\n")
		case utils.OutputModeYAML:
			bytes, err := yaml.Marshal(extraInfoMap)
			if err != nil {
				return fmt.Errorf("marshalling image and extra info to YAML: %w", err)
			}
			fmt.Fprint(cmd.OutOrStdout(), string(bytes))
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

	// We don't want to add the headless-related flags to the inspect command
	skipParams := []string{"!attach"}

	for _, operatorParams := range opGlobalParams {
		common.AddOCIFlags(cmd, operatorParams, skipParams, runtime)
	}
	common.AddOCIFlags(cmd, ociParams, skipParams, runtime)
	common.AddOCIFlags(cmd, runtimeGlobalParams, skipParams, runtime)
	common.AddOCIFlags(cmd, runtimeParams, skipParams, runtime)

	return cmd
}
