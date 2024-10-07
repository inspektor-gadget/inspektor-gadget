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

package common

import (
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

type testMode int

const (
	testModeBoth testMode = iota
	testModeInteractiveOnly
	testModeDetachOnly
)

type testSpec struct {
	Name           string
	Manifest       string
	Mode           testMode
	AdditionalArgs []string
	ExpectedParams api.ParamValues
	ExpectedName   string
	ExpectedID     string
	ExpectedTags   []string
	ExpectError    bool
}

type testRuntime struct {
	grpcruntime.Runtime
	t        *testing.T
	testSpec *testSpec
}

func (r *testRuntime) Init(*params.Params) error {
	return nil
}

func (r *testRuntime) Close() error {
	return nil
}

func (r *testRuntime) GetGadgetInfo(gadgetCtx runtime.GadgetContext, runtimeParams *params.Params, paramValueMap api.ParamValues) (*api.GadgetInfo, error) {
	panic("unimplemented")
}

func (r *testRuntime) RunGadget(gadgetCtx runtime.GadgetContext, runtimeParams *params.Params, paramValueMap api.ParamValues) error {
	if r.testSpec.ExpectedID != "" {
		assert.Equal(r.t, r.testSpec.ExpectedID, runtimeParams.Get(grpcruntime.ParamID).AsString())
	}
	if r.testSpec.ExpectedName != "" {
		assert.Equal(r.t, r.testSpec.ExpectedName, runtimeParams.Get(grpcruntime.ParamName).AsString())
	}
	if r.testSpec.ExpectedTags != nil {
		assert.Equal(r.t, r.testSpec.ExpectedTags, runtimeParams.Get(grpcruntime.ParamTags).AsStringSlice())
	}
	for k, v := range r.testSpec.ExpectedParams {
		val, ok := paramValueMap[k]
		require.True(r.t, ok, "expected paramValue exists for %q", k)
		require.Equal(r.t, v, val)
	}
	return nil
}

func createTempManifest(t *testing.T, manifest string) (string, error) {
	f, err := os.CreateTemp("", "manifest")
	if err != nil {
		return "", fmt.Errorf("creating temp manifest file: %w", err)
	}
	t.Cleanup(func() {
		os.Remove(f.Name())
	})
	_, err = f.WriteString(manifest)
	if err != nil {
		return "", fmt.Errorf("writing temp manifest: %w", err)
	}
	return f.Name(), nil
}

func TestRunWithSpec(t *testing.T) {
	tests := []*testSpec{
		{
			Name:           "specified image on command line",
			ExpectError:    true,
			AdditionalArgs: []string{"trace_exec"},
			Manifest: `
apiVersion: 1
kind: instance-spec
image: trace_exec
`,
		},
		{
			Name: "invalid version",
			Manifest: `
apiVersion: a`,
			ExpectError: true,
		},
		{
			Name: "invalid kind",
			Manifest: `
apiVersion: 1
kind: yo`,
			ExpectError: true,
		},
		{
			Name: "one spec with id, name, tags and params",
			Manifest: `
apiVersion: 1
kind: instance-spec
image: demo
id: 00000000000000000000000000000000
name: myinstancename
tags:
  - tag1
  - tag2
paramValues:
  a: b
  y: z
  n: 1
`,
			ExpectedID:   "00000000000000000000000000000000",
			ExpectedName: "myinstancename",
			ExpectedTags: []string{"tag1", "tag2"},
			ExpectedParams: map[string]string{
				"a": "b",
				"y": "z",
				"n": "1",
			},
		},
		{
			Name: "multiple specs with detach",
			Manifest: `
apiVersion: 1
kind: instance-spec
image: demo
---
apiVersion: 1
kind: instance-spec
image: demo
`,
			Mode: testModeDetachOnly,
		},
		{
			Name: "multiple specs without detach",
			Manifest: `
apiVersion: 1
kind: instance-spec
image: demo
---
apiVersion: 1
kind: instance-spec
image: demo
`,
			Mode:        testModeInteractiveOnly,
			ExpectError: true,
		},
		{
			Name: "multiple specs, one invalid",
			Manifest: `
apiVersion: 1
kind: instance-spec
image: demo
---
apiVersion: x
`,
			Mode:        testModeInteractiveOnly,
			ExpectError: true,
		},
		{
			Name: "missing image",
			Manifest: `
apiVersion: 1
kind: instance-spec
`,
			ExpectError: true,
		},
		{
			Name: "invalid id",
			Manifest: `
apiVersion: 1
kind: instance-spec
image: demo
id: 0
`,
			ExpectError: true,
		},
		{
			Name: "invalid name",
			Manifest: `
apiVersion: 1
kind: instance-spec
image: demo
name: invalid-#name*
`,
			ExpectError: true,
		},
	}

	environment.Environment = environment.Local

	for _, tt := range tests {
		runTest := func(detach bool) func(t *testing.T) {
			return func(t *testing.T) {
				fn, err := createTempManifest(t, tt.Manifest)
				require.NoError(t, err)
				rt := &testRuntime{
					t:        t,
					testSpec: tt,
				}
				root := &cobra.Command{}

				root.AddCommand(NewRunCommand(root, rt, []string{}, CommandModeRun))
				args := []string{"run", "-f", fn}
				if detach {
					args = append(args, "--detach")
				}
				args = append(args, tt.AdditionalArgs...)
				root.SetArgs(args)
				err = root.Execute()
				if tt.ExpectError {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}
		}
		if tt.Mode == testModeInteractiveOnly || tt.Mode == testModeBoth {
			t.Run(tt.Name, runTest(false))
		}
		if tt.Mode == testModeDetachOnly || tt.Mode == testModeBoth {
			t.Run(tt.Name, runTest(true))
		}
	}
}
