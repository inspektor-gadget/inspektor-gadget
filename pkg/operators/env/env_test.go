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

package env

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func TestEnv(t *testing.T) {
	demoEnvVar := "DEMO_ENV_VAR"
	demoEnvVal := "Ahoy!"
	demoFieldName := "env"
	os.Setenv(demoEnvVar, demoEnvVal)
	o := &envOperator{}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamEnvVars, demoEnvVar)
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "test")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationPrefix+demoFieldName, demoEnvVar)
		require.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		data, err := ds.NewPacketSingle()
		assert.NoError(t, err)
		err = ds.EmitAndRelease(data)
		assert.NoError(t, err)
		cancel()
		return nil
	}
	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	success := false
	consume := func(gadgetCtx operators.GadgetContext) error {
		ds := gadgetCtx.GetDataSources()["test"]
		require.NotNil(t, ds)

		field := ds.GetField(demoFieldName)
		require.NotNil(t, field)

		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			sv, err := field.String(data)
			require.NoError(t, err)
			assert.Equal(t, demoEnvVal, sv)
			success = true
			return nil
		}, 1000)
		return nil
	}
	consumer := simple.New("consumer",
		simple.WithPriority(Priority-1),
		simple.OnPreStart(consume),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer, consumer))
	err = gadgetCtx.Run(nil)
	require.NoError(t, err)

	assert.True(t, success)
}

func TestEnvForbidden(t *testing.T) {
	demoEnvVar := "DEMO_ENV_VAR"
	demoEnvVal := "Ahoy!"
	demoFieldName := "env"
	os.Setenv(demoEnvVar, demoEnvVal)
	o := &envOperator{}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	// Omitting setting ParamEnvVars here
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "test")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationPrefix+demoFieldName, demoEnvVar)
		require.NoError(t, err)
		return nil
	}
	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))
	err = gadgetCtx.Run(nil)
	require.Error(t, err)
}
