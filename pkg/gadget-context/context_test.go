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

package gadgetcontext

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// newSimpleOperator takes a name, a priority and a pointer to a string that the operator writes its name
// to during instantiation
func newSimpleOperator(name string, priority int, write *string, cancel func()) operators.DataOperator {
	return simple.New(name, simple.WithPriority(priority),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			*write += name
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			cancel()
			return nil
		}),
	)
}

func TestOperatorOrder(t *testing.T) {
	type operatorConfig struct {
		name     string
		priority int
	}
	type testCase struct {
		name          string
		operators     []operatorConfig
		expectedOrder string
	}
	testCases := []testCase{
		{
			name: "distinct priority",
			operators: []operatorConfig{
				{name: "b", priority: 1},
				{name: "a", priority: 0},
			},
			expectedOrder: "ab",
		},
		{
			name: "same priority",
			operators: []operatorConfig{
				{name: "b", priority: 0},
				{name: "a", priority: 0},
				{name: "c", priority: 0},
			},
			expectedOrder: "abc",
		},
	}
	for _, tc := range testCases {
		out := ""
		t.Run("", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var ops []operators.DataOperator
			for _, op := range tc.operators {
				ops = append(ops, newSimpleOperator(op.name, op.priority, &out, cancel))
			}
			err := New(ctx, "", WithDataOperators(ops...)).Run(nil)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOrder, out)
		})
	}
}

func TestParamsDefault(t *testing.T) {
	op := &fakeOperator{
		name:     "fake",
		priority: 0,
	}

	opts := WithDataOperators(op)

	ctx := New(t.Context(), "", opts)
	metadata := `
paramDefaults:
  operator.fake.foo: "123"
`

	ctx.SetMetadata([]byte(metadata))
	err := ctx.PrepareGadgetInfo(nil)
	require.NoError(t, err)

	info, err := ctx.SerializeGadgetInfo(false)
	require.NoError(t, err)

	for _, p := range info.Params {
		if p.Key == "foo" {
			require.Equal(t, "123", p.DefaultValue)
			return
		}
	}

	t.Fatalf("param not found")
}

func TestProcessCustomParams(t *testing.T) {
	tests := []struct {
		name                    string
		metadata                string
		paramValues             map[string]string
		expectedParams          []string
		expectedError           bool
		expectedMetadataChanges map[string]interface{}
	}{
		{
			name:                    "no custom params",
			metadata:                `name: test-gadget`,
			paramValues:             nil,
			expectedParams:          []string{},
			expectedError:           false,
			expectedMetadataChanges: nil,
		},
		{
			name: "single custom param with no values and no patch",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      defaultValue: "default"
      alias: "m"`,
			paramValues:             nil,
			expectedParams:          []string{},
			expectedError:           false, // It doesn't fail here but it should fail at build time (TODO)
			expectedMetadataChanges: nil,
		},
		{
			name: "single custom param with values but no paramValues (simulating GetGadgetInfo path)",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      defaultValue: "verbose"
      alias: "m"
      values:
        verbose:
          patch:
            debug: true
        quiet:
          patch:
            debug: false`,
			paramValues:             nil,
			expectedParams:          []string{"mode"},
			expectedError:           false,
			expectedMetadataChanges: nil, // No changes expected as paramValues are not provided
		},
		{
			name: "single custom param with empty patch",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      defaultValue: "verbose"
      alias: "m"
      values:
        verbose:
          patch:
        quiet:
          patch:
            debug: false`,
			paramValues:             map[string]string{"custom.mode": "verbose"},
			expectedParams:          []string{"mode"},
			expectedError:           false, // Shouldn't this fail?
			expectedMetadataChanges: nil,   // No changes expected as patch is empty
		},
		{
			name: "custom param with global patch fallback",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      defaultValue: "verbose"
      patch:
        global: true
      values:
        verbose:
          # No patch here, should use global fallback (global: true)
        quiet:
          patch:
            debug: false`,
			paramValues:             map[string]string{"custom.mode": "verbose"},
			expectedParams:          []string{"mode"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"global": true},
		},
		{
			name: "custom param with simple patch",
			metadata: `
params:
  custom:
    target:
      description: "Target specification"
      defaultValue: "local"
      values:
        local:
          patch:
            target.host: "localhost"
            target.port: "8080"`,
			paramValues:             map[string]string{"custom.target": "local"},
			expectedParams:          []string{"target"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"target.host": "localhost", "target.port": "8080"},
		},
		{
			name: "invalid template syntax",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      values:
        verbose:
          patch:
            target: "{{.invalidTemplate"`,
			paramValues:             map[string]string{"custom.mode": "verbose"},
			expectedParams:          []string{"mode"},
			expectedError:           true,
			expectedMetadataChanges: nil,
		},
		{
			name: "template execution error",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      values:
        verbose:
          patch:
            target: "{{call .nonExistentFunction \"test\"}}"`,
			paramValues:             map[string]string{"custom.mode": "verbose"},
			expectedParams:          []string{"mode"},
			expectedError:           true,
			expectedMetadataChanges: nil,
		},
		{
			name: "template execution error with invalid function arguments",
			metadata: `
params:
  custom:
    mode:
      description: "Operating mode"
      values:
        verbose:
          patch:
            target: "{{call .getConfig}}"`, // Missing required argument
			paramValues:             map[string]string{"custom.mode": "verbose"},
			expectedParams:          []string{"mode"},
			expectedError:           true,
			expectedMetadataChanges: nil,
		},
		{
			name: "template using getConfig function",
			metadata: `
name: test-gadget
target:
  host: "default-host"
  port: 8080
params:
  custom:
    connection:
      description: "Connection configuration"
      defaultValue: "default"
      values:
        default:
          patch:
            connection:
              url: "http://{{call .getConfig \"target.host\"}}:{{call .getConfig \"target.port\"}}/api"
        custom:
          patch:
            connection:
              url: "http://custom-host:9090/api"`,
			paramValues:             map[string]string{"custom.connection": "default"},
			expectedParams:          []string{"connection"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"connection.url": "http://default-host:8080/api"},
		},
		{
			name: "template using getParamValue function",
			metadata: `
name: test-gadget
params:
  ebpf:
    debug:
      key: debug
      defaultValue: "false"
      description: "Enable debug mode for eBPF program"
  custom:
    target_env:
      description: "Target environment"
      defaultValue: "production"
      values:
        production:
          patch:
            deployment:
              environment: "production"
              debug: "{{call .getParamValue \"ebpf.debug\"}}"
              replicas: 3
        development:
          patch:
            deployment:
              environment: "development"
              debug: "{{call .getParamValue \"ebpf.debug\"}}"
              replicas: 1`,
			paramValues:             map[string]string{"custom.target_env": "development", "ebpf.debug": "true"},
			expectedParams:          []string{"target_env"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"deployment.environment": "development", "deployment.debug": "true", "deployment.replicas": 1},
		},
		{
			name: "patch datasource annotations",
			metadata: `
name: test-gadget
datasources:
  processes:
    annotations:
      cli.clear-screen-before: "false"
params:
  custom:
    clear_screen:
      description: "Clear screen before output"
      defaultValue: "enabled"
      values:
        enabled:
          patch:
            datasources:
              processes:
                annotations:
                  cli.clear-screen-before: "true"
        disabled:
          patch:
            datasources:
              processes:
                annotations:
                  cli.clear-screen-before: "false"`,
			paramValues:             map[string]string{"custom.clear_screen": "enabled"},
			expectedParams:          []string{"clear_screen"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"datasources.processes.annotations.cli.clear-screen-before": "true"},
		},
		{
			name: "patch field annotations",
			metadata: `
name: test-gadget
datasources:
  events:
    fields:
      pid:
        annotations:
          columns.width: "8"
params:
  custom:
    pid_width:
      description: "Width of PID column"
      defaultValue: "normal"
      values:
        normal:
          patch:
            datasources:
              events:
                fields:
                  pid:
                    annotations:
                      columns.width: "8"
        wide:
          patch:
            datasources:
              events:
                fields:
                  pid:
                    annotations:
                      columns.width: "12"`,
			paramValues:             map[string]string{"custom.pid_width": "wide"},
			expectedParams:          []string{"pid_width"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"datasources.events.fields.pid.annotations.columns.width": "12"},
		},
		{
			name: "patch operator configuration and patching multiple fields",
			metadata: `
name: test-gadget
operator:
  process:
    interval: 1s
params:
  custom:
    interval:
      description: "Interval to re-read statistics"
      defaultValue: "3s"
      values:
        fast:
          patch:
            operator:
              process:
                interval: "1s"
                anotherConfig: true
        slow:
          patch:
            operator:
              process:
                interval: "10s"
                anotherConfig: false`,
			paramValues:             map[string]string{"custom.interval": "fast"},
			expectedParams:          []string{"interval"},
			expectedError:           false,
			expectedMetadataChanges: map[string]interface{}{"operator.process.interval": "1s", "operator.process.anotherConfig": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new gadget context with a mock logger
			ctx := New(context.Background(), "test-image")

			// Set up viper with the test configuration
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tt.metadata))
			require.NoError(t, err)

			// Store the original viper for comparison
			originalViper := v

			// Call the function under test
			err = ctx.processCustomParams(v, tt.paramValues)

			// Check error expectations
			if tt.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Check the parameters were added to the context
			params := ctx.Params()
			assert.Len(t, params, len(tt.expectedParams))

			// Check that the expected keys (params' name) are present
			actualKeys := make([]string, len(params))
			for i, p := range params {
				// Verify the prefix is always "custom."
				assert.Equal(t, "custom.", p.Prefix)
				actualKeys[i] = p.Key
			}
			for _, expectedKey := range tt.expectedParams {
				assert.Contains(t, actualKeys, expectedKey)
			}

			// Validate configuration changes
			currentViper := v
			if len(tt.expectedMetadataChanges) == 0 {
				// Configuration should remain completely unchanged
				assert.Equal(t, originalViper.AllSettings(), currentViper.AllSettings(), "Configuration should not have changed")
			} else {
				// Configuration should contain exactly the expected changes and nothing more
				// Apply expected changes to original config
				for key, value := range tt.expectedMetadataChanges {
					originalViper.Set(key, value)
				}
				assert.Equal(t, originalViper.AllSettings(), currentViper.AllSettings(), "Configuration should contain exactly the expected changes")
			}
		})
	}
}
