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
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/stretchr/testify/require"
)

type testDef struct {
	testName             string
	fieldKey             string
	expectedDefaultValue string
}

func TestParamDefaults(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	t.Parallel()

	info, err := getGadgetInfo("ci/metadata", true)
	require.NoError(t, err, "Failed to extract gadget info")
	require.NotNil(t, info, "Gadget info should not be nil")

	params := info.Params
	require.NotNil(t, params, "Gadget parameters should not be nil")

	for _, def := range []testDef{
		{
			testName:             "Overwrite default values for an eBPF param from paramDefaults section",
			fieldKey:             "iface",
			expectedDefaultValue: "ifaceFromParamsDefaults",
		},
		// This is failing as the default value in eBPF code is overwriting the one from params section.
		// Probably a bug!
		// {
		// 	testName:             "Overwrite default values for an eBPF param from params section",
		// 	fieldKey:             "ppid",
		// 	expectedDefaultValue: "123",
		// },
		{
			testName:             "Don't overwrite default value for an eBPF param",
			fieldKey:             "pid",
			expectedDefaultValue: "10",
		},
		// TODO: Avoid using hardcoded oci params in tests. These should be
		// params of a dummy operator we add only for this test.
		{
			testName:             "Overwrite default values for an operator instance param",
			fieldKey:             "pull",
			expectedDefaultValue: "pullFromParamsDefaults",
		},
		{
			testName:             "Don't overwrite default value for an operator instance param",
			fieldKey:             "validate-metadata",
			expectedDefaultValue: "true",
		},
	} {
		t.Run(def.fieldKey, func(t *testing.T) {
			t.Parallel()

			var p *api.Param
			for _, param := range params {
				if param.GetKey() == def.fieldKey {
					p = param
					break
				}
			}

			require.NotNil(t, p, fmt.Sprintf("Expected '%s' parameter to be present", def.fieldKey))
			require.Equal(t, def.expectedDefaultValue, p.GetDefaultValue(), fmt.Sprintf("unexpected default value for '%s' parameter", def.fieldKey))
		})
	}
}

// TODO: Move this to gadgettesting package (It's also used by other tests)
func getGadgetInfo(imageName string, extraInfo bool) (*api.GadgetInfo, error) {
	image := gadgetrunner.GetGadgetImageName(imageName)

	opGlobalParams := make(map[string]*params.Params)
	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()

	ocihandler.OciHandler.Init(ociParams)

	opGlobalParams["oci"] = apihelpers.ToParamDescs(ocihandler.OciHandler.GlobalParams()).ToParams()
	verifyImage := strings.ToLower(os.Getenv("IG_VERIFY_IMAGE"))
	if verifyImage == "true" || verifyImage == "false" {
		opGlobalParams["oci"].Set("verify-image", verifyImage)
	}

	runtime := local.New()
	runtimeParams := runtime.ParamDescs().ToParams()

	ops := make([]operators.DataOperator, 0)
	err := ocihandler.OciHandler.Init(opGlobalParams["oci"])
	if err != nil {
		return nil, fmt.Errorf("Error initializing OCI handler: %w\n", err)
	}
	ops = append(ops, ocihandler.OciHandler)

	gadgetContextOps := []gadgetcontext.Option{
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.IncludeExtraInfo(extraInfo),
	}

	if strings.ToLower(os.Getenv("IG_DEBUG_LOGS")) == "true" {
		l := logger.DefaultLogger()
		l.SetLevel(logger.DebugLevel)
		gadgetContextOps = append(gadgetContextOps, gadgetcontext.WithLogger(l))
	}

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		image,
		gadgetContextOps...,
	)

	paramValueMap := make(map[string]string)
	ociParams.CopyToMap(paramValueMap, "operator.oci.")

	info, err := runtime.GetGadgetInfo(gadgetCtx, runtimeParams, paramValueMap)
	if err != nil {
		return nil, fmt.Errorf("Error getting gadget info: %w\n", err)
	}
	return info, nil
}
