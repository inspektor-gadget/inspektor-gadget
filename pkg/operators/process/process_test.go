// Copyright 2024-2025 The Inspektor Gadget authors
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

package process

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

type testSubscriber struct {
	events []datasource.Data
}

func (s *testSubscriber) handleEvent(ds datasource.DataSource, data datasource.Data) error {
	s.events = append(s.events, data)
	return nil
}

func TestProcessOperator(t *testing.T) {
	// Create a viper config with process monitoring enabled
	config := viper.New()
	config.Set(configKeyEnabled, true)
	config.Set(configKeyInterval, "100ms") // Use a short interval for testing

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Create a subscriber to collect events
	subscriber := &testSubscriber{events: make([]datasource.Data, 0)}

	// Create a simple operator to set up the config and subscribe to events
	setupOp := simple.New("setup",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Set the config in the context
			gadgetCtx.SetVar("config", config)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			// Subscribe to the processes data source
			ds := gadgetCtx.GetDataSources()["processes"]
			require.NotNil(t, ds)

			err := ds.Subscribe(subscriber.handleEvent, Priority+1)
			require.NoError(t, err)

			return nil
		}),
	)

	// Create the gadget context with the process operator and setup operator
	op := &processOperator{}
	gadgetCtx := gadgetcontext.New(ctx, "test", gadgetcontext.WithDataOperators(op, setupOp))

	// Run the gadget
	err := gadgetCtx.Run(api.ParamValues{})
	require.NoError(t, err)

	// Verify that events were emitted
	assert.Greater(t, len(subscriber.events), 0)
}

func TestProcessOperatorWithFields(t *testing.T) {
	// Create a viper config with process monitoring enabled and specific fields
	config := viper.New()
	config.Set(configKeyEnabled, true)
	config.Set(configKeyInterval, "100ms") // Use a short interval for testing
	config.Set(configKeyFields, []string{"comm", "pid", "ppid"})

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Create a subscriber to collect events
	subscriber := &testSubscriber{events: make([]datasource.Data, 0)}

	// Create a simple operator to set up the config and subscribe to events
	setupOp := simple.New("setup",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Set the config in the context
			gadgetCtx.SetVar("config", config)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			// Subscribe to the processes data source
			ds := gadgetCtx.GetDataSources()["processes"]
			require.NotNil(t, ds)

			// Verify that only the specified fields were created
			accessors := ds.Accessors(false)
			fieldNames := make(map[string]bool)
			for _, accessor := range accessors {
				fieldNames[accessor.Name()] = true
			}

			assert.True(t, fieldNames["pid"])
			assert.True(t, fieldNames["ppid"])
			assert.True(t, fieldNames["comm"])
			assert.False(t, fieldNames["cpuUsage"])
			assert.False(t, fieldNames["memoryRSS"])

			err := ds.Subscribe(subscriber.handleEvent, Priority+1)
			require.NoError(t, err)

			return nil
		}),
	)

	// Create the gadget context with the process operator and setup operator
	op := &processOperator{}
	gadgetCtx := gadgetcontext.New(ctx, "test", gadgetcontext.WithDataOperators(op, setupOp))

	// Run the gadget
	err := gadgetCtx.Run(api.ParamValues{})
	require.NoError(t, err)

	// Verify that events were emitted
	assert.Greater(t, len(subscriber.events), 0)
}

func TestProcessOperatorDisabled(t *testing.T) {
	// Create a viper config with process monitoring disabled
	config := viper.New()
	config.Set(configKeyEnabled, false)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Create a simple operator to set up the config
	setupOp := simple.New("setup",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Set the config in the context
			gadgetCtx.SetVar("config", config)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			// Verify that the processes data source was not created
			ds := gadgetCtx.GetDataSources()["processes"]
			assert.Nil(t, ds)
			return nil
		}),
	)

	// Create the gadget context with the process operator and setup operator
	op := &processOperator{}
	gadgetCtx := gadgetcontext.New(ctx, "test", gadgetcontext.WithDataOperators(op, setupOp))

	// Run the gadget
	err := gadgetCtx.Run(api.ParamValues{})
	require.NoError(t, err)
}
