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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

func TestTraceloop(t *testing.T) {
	// TODO: This is a dummy test to check that the gadget runs without errors.
	// It should be extended to check that the gadget produces correct data.
	gadgettesting.InitUnitTest(t)

	// TODO: This is the minimum kernel version the gadget works on among the
	// ones we test. We need to check if it works with other versions that we
	// don't test, like 5.9
	gadgettesting.MinimumKernelVersion(t, "5.10")

	// This gadget requires the containers datasource, create a dummy operator to register it
	myOp := simple.New("myop",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "containers")
			require.NoError(t, err)

			_, err = ds.AddField("event_type", api.Kind_String)
			require.NoError(t, err)

			_, err = ds.AddField("mntns_id", api.Kind_Uint64)
			require.NoError(t, err)

			_, err = ds.AddField("name", api.Kind_String)
			require.NoError(t, err)

			return nil
		}),
	)

	opts := gadgetrunner.GadgetRunnerOpts[any]{
		Image:   "traceloop",
		Timeout: 5 * time.Second,
		ParamValues: map[string]string{
			"operator.oci.wasm.syscall-filters": "",
		},
	}

	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
	gadgetRunner.DataOperator = append(gadgetRunner.DataOperator, myOp)
	gadgetRunner.RunGadget()
}
