// Copyright 2023 The Inspektor Gadget authors
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

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/frontends"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	OutputModeColumns    = "columns"
	OutputModeJSON       = "json"
	OutputModeJSONPretty = "jsonpretty"
	OutputModeYAML       = "yaml"
)

// PrepareAndRunGadget runs a gadget with all required info.
// runtime and operators have to be initialized before calling this function
func PrepareAndRunGadget(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	runtimeParams *params.Params,
	gadgetDesc gadgets.GadgetDesc,
	gadgetParams *params.Params,
	args []string,
	operators operators.Operators,
	operatorsParamsCollection params.Collection,
	parser parser.Parser,
	log logger.Logger,
	timeout time.Duration,
	outputModeName string,
	outputModeParams string,
	fe frontends.Frontend,
	filters []string,
) error {
	// Handle timeout parameter by adding a timeout to the context
	if timeout != 0 {
		if gadgetDesc.Type().IsPeriodic() {
			interval := time.Duration(gadgetParams.Get(gadgets.ParamInterval).AsInt()) * time.Second
			if timeout < interval {
				return fmt.Errorf("timeout must be greater than interval")
			}
			if timeout%interval != 0 {
				return fmt.Errorf("timeout must be a multiple of interval")
			}
		}
	}

	gadgetCtx := gadgetcontext.New(
		ctx,
		id,
		runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		args,
		operatorsParamsCollection,
		parser,
		log,
		timeout,
	)
	defer gadgetCtx.Cancel()

	if parser == nil {
		var transformResult func(any) ([]byte, error)

		switch outputModeName {
		default:
			transformer, ok := gadgetDesc.(gadgets.GadgetOutputFormats)
			if !ok {
				return fmt.Errorf("gadget does not provide output formats")
			}
			formats, _ := transformer.OutputFormats()
			if _, ok := formats[outputModeName]; !ok {
				return fmt.Errorf("invalid output mode %q", outputModeName)
			}

			transformResult = formats[outputModeName].Transform
		case OutputModeJSON:
			transformResult = func(result any) ([]byte, error) {
				r, _ := result.([]byte)
				return r, nil
			}
		case OutputModeJSONPretty:
			printEventAsJSONPrettyFn(fe)
		case OutputModeYAML:
			printEventAsYAMLFn(fe)
		}

		gType := gadgetDesc.Type()
		if timeout == 0 && gType != gadgets.TypeTrace && gType != gadgets.TypeTraceIntervals {
			gadgetCtx.Logger().Info("Running. Press Ctrl + C to finish")
		}

		// This kind of gadgets return directly the result instead of
		// using the parser. We allow partial results, so error is only
		// returned after handling those results.
		results, err := runtime.RunGadget(gadgetCtx)

		for node, result := range results {
			if result.Error != nil {
				continue
			}
			transformed, err := transformResult(result.Payload)
			if err != nil {
				gadgetCtx.Logger().Warnf("transform result for %q failed: %v", node, err)
				continue
			}
			results[node].Payload = transformed
		}

		if len(results) == 1 {
			// still need to iterate as we don't necessarily know the key
			for _, result := range results {
				fe.Output(string(result.Payload))
			}
		} else {
			format := "%s: %s"
			for _, result := range results {
				// Check, whether we have a multi-line payload and adjust the output accordingly
				if bytes.Contains(result.Payload, []byte("\n")) {
					format = "\n---\n%s:\n%s"
					break
				}
			}
			for key, result := range results {
				fe.Output(fmt.Sprintf(format, key, string(result.Payload)))
			}
		}

		return err
	}

	// Add filters if requested
	if len(filters) > 0 {
		err := parser.SetFilters(filters)
		if err != nil {
			return fmt.Errorf("setting filters: %w", err)
		}
	}

	if gadgetDesc.Type().CanSort() {
		sortBy := gadgetParams.Get(gadgets.ParamSortBy).AsStringSlice()
		err := parser.SetSorting(sortBy)
		if err != nil {
			return fmt.Errorf("setting sort order: %w", err)
		}
	}

	formatter := parser.GetTextColumnsFormatter()

	requestedStandardColumns := outputModeParams == ""
	requestedColumns := strings.Split(outputModeParams, ",")

	// If the standard columns are requested, hide columns that would be empty without specific features
	// (bool params) enabled
	if requestedStandardColumns {
		var hiddenTags []string
		if gadgetParams != nil {
			for _, param := range *gadgetParams {
				if param.TypeHint == params.TypeBool {
					if !param.AsBool() {
						hiddenTags = append(hiddenTags, "param:"+strings.ToLower(param.Key))
					}
				}
			}
		}
		requestedColumns = parser.GetDefaultColumns(hiddenTags...)
	}

	valid, invalid := parser.VerifyColumnNames(requestedColumns)

	for _, c := range invalid {
		log.Warnf("column %q not found", c)
	}

	if err := formatter.SetShowColumns(valid); err != nil {
		return err
	}

	parser.SetLogCallback(fe.Logf)

	// Wire up callbacks before handing over to runtime depending on the output mode
	switch outputModeName {
	default:
		transformer, ok := gadgetDesc.(gadgets.GadgetOutputFormats)
		if !ok {
			return fmt.Errorf("gadget does not provide output formats")
		}
		formats, _ := transformer.OutputFormats()
		if _, ok := formats[outputModeName]; !ok {
			return fmt.Errorf("invalid output mode %q", outputModeName)
		}

		format := formats[outputModeName]

		if format.RequiresCombinedResult {
			parser.EnableCombiner()
		}

		transformResult := format.Transform
		parser.SetEventCallback(func(ev any) {
			transformed, err := transformResult(ev)
			if err != nil {
				fe.Logf(logger.WarnLevel, "could not transform event: %v", err)
				return
			}
			fe.Output(string(transformed))
		})
	case OutputModeColumns:
		formatter.SetEventCallback(fe.Output)

		// Enable additional output, if the gadget supports it (e.g. profile/cpu)
		//  TODO: This can be optimized later on
		formatter.SetEnableExtraLines(true)

		parser.SetEventCallback(formatter.EventHandlerFunc())
		if gadgetDesc.Type().IsPeriodic() {
			// In case of periodic outputting gadgets, this is done as full table output, and we need to
			// clear the screen for every interval, that's why we add fe.Clear here
			parser.SetEventCallback(formatter.EventHandlerFuncArray(
				fe.Clear,
				func() {
					fe.Output(formatter.FormatHeader())
				},
			))

			// Print first header while we wait for input
			if fe.IsTerminal() {
				fe.Clear()
				fe.Output(formatter.FormatHeader())
			}
			break
		}
		fe.Output(formatter.FormatHeader())
		parser.SetEventCallback(formatter.EventHandlerFuncArray())
	case OutputModeJSON:
		jsonCallback := printEventAsJSONFn(fe)
		if cjson, ok := gadgetDesc.(gadgets.GadgetJSONConverter); ok {
			jsonCallback = cjson.JSONConverter(gadgetParams, fe)
		}
		parser.SetEventCallback(jsonCallback)
	case OutputModeJSONPretty:
		jsonPrettyCallback := printEventAsJSONFn(fe)
		if cjson, ok := gadgetDesc.(gadgets.GadgetJSONPrettyConverter); ok {
			jsonPrettyCallback = cjson.JSONPrettyConverter(gadgetParams, fe)
		}
		parser.SetEventCallback(jsonPrettyCallback)
	case OutputModeYAML:
		yamlCallback := printEventAsYAMLFn(fe)
		if cyaml, ok := gadgetDesc.(gadgets.GadgetYAMLConverter); ok {
			yamlCallback = cyaml.YAMLConverter(gadgetParams, fe)
		}
		parser.SetEventCallback(yamlCallback)
	}

	// Gadgets with parser don't return anything, they provide the
	// output via the parser
	_, err := runtime.RunGadget(gadgetCtx)
	if err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	return nil
}

func printEventAsJSONFn(fe frontends.Frontend) func(ev any) {
	return func(ev any) {
		d, err := json.Marshal(ev)
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshaling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}

func printEventAsJSONPrettyFn(fe frontends.Frontend) func(ev any) {
	return func(ev any) {
		d, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshaling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}

func printEventAsYAMLFn(fe frontends.Frontend) func(ev any) {
	return func(ev any) {
		d, err := k8syaml.Marshal(ev)
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshaling %+v: %s", ev, err)
			return
		}
		fe.Output("---\n" + string(d))
	}
}
