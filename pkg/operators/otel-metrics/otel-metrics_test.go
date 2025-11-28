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

package otelmetrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func checkForKeys(t *testing.T, attributes []attribute.KeyValue) {
	foundDynamicKey := false
	foundStaticInt := false
	foundStaticFloat := false
	foundStaticString := false
	for _, a := range attributes {
		if a.Key == "foo" {
			foundDynamicKey = true
			assert.Equal(t, "foobar", a.Value.AsString())
		}
		if a.Key == "testint" {
			foundStaticInt = true
			assert.Equal(t, int64(1337), a.Value.AsInt64())
		}
		if a.Key == "testfloat" {
			foundStaticFloat = true
			assert.Equal(t, float64(133.7), a.Value.AsFloat64())
		}
		if a.Key == "teststring" {
			foundStaticString = true
			assert.Equal(t, "IGr0x", a.Value.AsString())
		}
	}
	assert.True(t, foundDynamicKey)
	assert.True(t, foundStaticInt)
	assert.True(t, foundStaticFloat)
	assert.True(t, foundStaticString)
}

func TestMetricsCounterAndGauge(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource
	var key datasource.FieldAccessor
	var ctr datasource.FieldAccessor
	var gauge datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")

		ds.AddAnnotation(AnnotationKeysPrefix+"testint"+AnnotationKeysValueSuffix, "1337")
		ds.AddAnnotation(AnnotationKeysPrefix+"testint"+AnnotationKeysTypeSuffix, "int64")

		ds.AddAnnotation(AnnotationKeysPrefix+"testfloat"+AnnotationKeysValueSuffix, "133.7")
		ds.AddAnnotation(AnnotationKeysPrefix+"testfloat"+AnnotationKeysTypeSuffix, "float64")

		ds.AddAnnotation(AnnotationKeysPrefix+"teststring"+AnnotationKeysValueSuffix, "IGr0x")
		ds.AddAnnotation(AnnotationKeysPrefix+"teststring"+AnnotationKeysTypeSuffix, "string")

		key, err = ds.AddField("foo", api.Kind_String, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeKey,
		}))
		require.NoError(t, err)

		ctr, err = ds.AddField("ctr", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeCounter,
		}))
		require.NoError(t, err)

		gauge, err = ds.AddField("gauge", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeGauge,
		}))
		require.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		for i := range 10 {
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			err = key.PutString(data, "foobar")
			require.NoError(t, err)
			err = ctr.PutUint32(data, uint32(1))
			assert.NoError(t, err)
			err = gauge.PutUint32(data, uint32(i))
			assert.NoError(t, err)
			err = ds.EmitAndRelease(data)
			assert.NoError(t, err)
		}
		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	err = gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name": "metrics:metrics",
	})

	require.NoError(t, err)

	md := &metricdata.ResourceMetrics{}

	err = o.exporter.Collect(context.Background(), md)
	require.NoError(t, err)

	assert.NotEmpty(t, md.ScopeMetrics)
	for _, sm := range md.ScopeMetrics {
		assert.NotEmpty(t, sm)
		foundCtr := false
		foundGauge := false
		for _, m := range sm.Metrics {
			if m.Name == "ctr" {
				foundCtr = true
				data, ok := (m.Data).(metricdata.Sum[int64])
				assert.True(t, ok)
				assert.Equal(t, int64(10), data.DataPoints[0].Value)

				// check keys
				checkForKeys(t, data.DataPoints[0].Attributes.ToSlice())
			}
			if m.Name == "gauge" {
				foundGauge = true
				data, ok := (m.Data).(metricdata.Gauge[int64])
				assert.True(t, ok)
				assert.Equal(t, int64(9), data.DataPoints[0].Value)

				// check keys
				checkForKeys(t, data.DataPoints[0].Attributes.ToSlice())
			}
		}
		assert.True(t, foundCtr)
		assert.True(t, foundGauge)
	}
}

func TestMetricsHistogram(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource
	var value datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	expectedBuckets := []uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 3, 2, 3, 0}

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")
		value, err = ds.AddField("duration", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeHistogram,
		}))
		require.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		for i := range 10 {
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			err = value.PutUint32(data, uint32((i+1)*1000))
			assert.NoError(t, err)
			err = ds.EmitAndRelease(data)
			assert.NoError(t, err)
		}
		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)

	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	err = gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name": "metrics:metrics",
	})
	require.NoError(t, err)

	md := &metricdata.ResourceMetrics{}

	err = o.exporter.Collect(context.Background(), md)
	require.NoError(t, err)

	assert.NotEmpty(t, md.ScopeMetrics)
	for _, sm := range md.ScopeMetrics {
		assert.NotEmpty(t, sm)
		found := false
		for _, m := range sm.Metrics {
			if m.Name == "duration" {
				found = true
				data, ok := (m.Data).(metricdata.Histogram[int64])
				assert.True(t, ok)
				assert.Equal(t, 1, len(data.DataPoints))
				assert.Equal(t, len(expectedBuckets), len(data.DataPoints[0].BucketCounts))
				assert.Equal(t, expectedBuckets, data.DataPoints[0].BucketCounts)
			}
		}
		assert.True(t, found)
	}
}
