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

package otelmetrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

func TestMetricsCounterAndGauge(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	err := o.Init(globalParams)
	require.NoError(t, err)

	var ds datasource.DataSource
	var ctr datasource.FieldAccessor
	var gauge datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "metrics")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")

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
			}
			if m.Name == "gauge" {
				foundGauge = true
				data, ok := (m.Data).(metricdata.Gauge[int64])
				assert.True(t, ok)
				assert.Equal(t, int64(9), data.DataPoints[0].Value)
			}
		}
		assert.True(t, foundCtr)
		assert.True(t, foundGauge)
	}
}

func collectIntMetric(t *testing.T, exporter *otelprometheus.Exporter, name string) map[string]int64 {
	t.Helper()

	md := &metricdata.ResourceMetrics{}
	require.NoError(t, exporter.Collect(context.Background(), md))
	return intMetricValues(t, md, name)
}

func intMetricValues(t *testing.T, md *metricdata.ResourceMetrics, name string) map[string]int64 {
	t.Helper()

	values := make(map[string]int64)
	for _, sm := range md.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, point := range data.DataPoints {
					values[point.Attributes.Encoded(attribute.DefaultEncoder())] = point.Value
				}
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					values[point.Attributes.Encoded(attribute.DefaultEncoder())] = point.Value
				}
			default:
				t.Fatalf("unexpected metric data type %T for %q", m.Data, name)
			}
		}
	}
	return values
}

type snapshotTestRow struct {
	key   string
	gauge uint32
}

func TestSnapshotMetricsTopTCP(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	require.NoError(t, o.Init(globalParams))

	var ds datasource.DataSource
	var key, gauge, counter datasource.FieldAccessor
	forwardedSnapshots := 0

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, "tcp")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")
		ds.AddAnnotation(AnnotationMetricsSnapshot, "true")
		ds.AddAnnotation(AnnotationMetricsSnapshotTimeout, time.Hour.String())

		key, err = ds.AddField("connection", api.Kind_String, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeKey,
		}))
		require.NoError(t, err)
		gauge, err = ds.AddField("sent_raw", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeGauge,
		}))
		require.NoError(t, err)
		counter, err = ds.AddField("packets", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeCounter,
		}))
		require.NoError(t, err)
		require.NoError(t, ds.SubscribeArray(func(datasource.DataSource, datasource.DataArray) error {
			forwardedSnapshots++
			return nil
		}, Priority+1))
		return nil
	}

	newSnapshot := func(rows ...snapshotTestRow) datasource.PacketArray {
		packet, err := ds.NewPacketArray()
		require.NoError(t, err)
		for _, row := range rows {
			data := packet.New()
			require.NoError(t, key.PutString(data, row.key))
			require.NoError(t, gauge.PutUint32(data, row.gauge))
			require.NoError(t, counter.PutUint32(data, 1))
			packet.Append(data)
		}
		return packet
	}

	produce := func(operators.GadgetContext) error {
		require.NoError(t, ds.EmitAndRelease(newSnapshot(
			snapshotTestRow{key: "A", gauge: 1},
			snapshotTestRow{key: "B", gauge: 2},
		)))
		assert.Equal(t, map[string]int64{"connection=A": 1, "connection=B": 2}, collectIntMetric(t, o.exporter, "sent_raw"))

		require.NoError(t, ds.EmitAndRelease(newSnapshot(
			snapshotTestRow{key: "A", gauge: 3},
		)))
		assert.Equal(t, map[string]int64{"connection=A": 3}, collectIntMetric(t, o.exporter, "sent_raw"))

		require.NoError(t, ds.EmitAndRelease(newSnapshot(
			snapshotTestRow{key: "A", gauge: 4},
			snapshotTestRow{key: "A", gauge: 5},
		)))
		assert.Equal(t, map[string]int64{"connection=A": 3}, collectIntMetric(t, o.exporter, "sent_raw"))
		assert.Equal(t, 3, forwardedSnapshots)

		require.NoError(t, ds.EmitAndRelease(newSnapshot()))
		assert.Empty(t, collectIntMetric(t, o.exporter, "sent_raw"))
		assert.Equal(t, map[string]int64{"connection=A": 4, "connection=B": 1}, collectIntMetric(t, o.exporter, "packets"))
		assert.Equal(t, 4, forwardedSnapshots)

		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)
	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	require.NoError(t, gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name": "tcp:tcp",
	}))
}

func TestSnapshotMetricsExpire(t *testing.T) {
	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	globalParams.Set(ParamOtelMetricsListen, "true")
	require.NoError(t, o.Init(globalParams))

	var ds datasource.DataSource
	var gauge datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, "expiring")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")
		ds.AddAnnotation(AnnotationMetricsSnapshot, "true")
		ds.AddAnnotation(AnnotationMetricsSnapshotTimeout, "25ms")
		gauge, err = ds.AddField("gauge", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeGauge,
		}))
		require.NoError(t, err)
		return nil
	}
	produce := func(operators.GadgetContext) error {
		packet, err := ds.NewPacketArray()
		require.NoError(t, err)
		data := packet.New()
		require.NoError(t, gauge.PutUint32(data, 1))
		packet.Append(data)
		require.NoError(t, ds.EmitAndRelease(packet))
		require.NotEmpty(t, collectIntMetric(t, o.exporter, "gauge"))

		require.Eventually(t, func() bool {
			return len(collectIntMetric(t, o.exporter, "gauge")) == 0
		}, time.Second, 10*time.Millisecond)
		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)
	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	require.NoError(t, gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name": "expiring:expiring",
	}))
}

func TestSnapshotMetricsConfiguredProvider(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		require.NoError(t, provider.Shutdown(context.Background()))
	})

	o := &otelMetricsOperator{skipListen: true}
	globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	require.NoError(t, o.Init(globalParams))
	o.providers["manual"] = provider

	var ds datasource.DataSource
	var key, gauge datasource.FieldAccessor

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	prepare := func(gadgetCtx operators.GadgetContext) error {
		var err error
		ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, "snapshot")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationMetricsCollect, "true")
		ds.AddAnnotation(AnnotationMetricsSnapshot, "true")
		ds.AddAnnotation(AnnotationMetricsSnapshotTimeout, time.Hour.String())
		key, err = ds.AddField("key", api.Kind_String, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeKey,
		}))
		require.NoError(t, err)
		gauge, err = ds.AddField("gauge", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
			AnnotationMetricsType: MetricTypeGauge,
		}))
		return err
	}
	produce := func(operators.GadgetContext) error {
		packet, err := ds.NewPacketArray()
		require.NoError(t, err)
		data := packet.New()
		require.NoError(t, key.PutString(data, "A"))
		require.NoError(t, gauge.PutUint32(data, 1))
		packet.Append(data)
		require.NoError(t, ds.EmitAndRelease(packet))

		md := &metricdata.ResourceMetrics{}
		require.NoError(t, reader.Collect(context.Background(), md))
		assert.Equal(t, map[string]int64{"key=A": 1}, intMetricValues(t, md, "gauge"))

		empty, err := ds.NewPacketArray()
		require.NoError(t, err)
		require.NoError(t, ds.EmitAndRelease(empty))
		md = &metricdata.ResourceMetrics{}
		require.NoError(t, reader.Collect(context.Background(), md))
		assert.Empty(t, intMetricValues(t, md, "gauge"))

		cancel()
		return nil
	}

	producer := simple.New("producer",
		simple.WithPriority(Priority-1),
		simple.OnInit(prepare),
		simple.OnStart(produce),
	)
	gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

	require.NoError(t, gadgetCtx.Run(api.ParamValues{
		"operator.otel-metrics.otel-metrics-name":     "snapshot:snapshot",
		"operator.otel-metrics.otel-metrics-exporter": "manual",
	}))
}

func TestSnapshotTimeout(t *testing.T) {
	tests := []struct {
		name          string
		fetchInterval string
		timeout       string
		expected      time.Duration
		errorContains string
	}{
		{
			name:     "configured without fetch interval",
			timeout:  "5s",
			expected: 5 * time.Second,
		},
		{
			name:          "configured with fetch interval",
			fetchInterval: "2s",
			timeout:       "5s",
			expected:      5 * time.Second,
		},
		{
			name:          "configured at minimum",
			fetchInterval: "2s",
			timeout:       "4s",
			expected:      4 * time.Second,
		},
		{
			name:          "configured below minimum",
			fetchInterval: "2s",
			timeout:       "3999ms",
			errorContains: "metrics.snapshot-timeout (3.999s) must be at least twice fetch-interval (2s)",
		},
		{
			name:          "derived from fetch interval",
			fetchInterval: "2s",
			expected:      6 * time.Second,
		},
		{
			name:          "missing",
			errorContains: AnnotationMetricsSnapshotTimeout,
		},
		{
			name:          "non-positive",
			timeout:       "0s",
			errorContains: "must be greater than zero",
		},
		{
			name:          "invalid",
			timeout:       "later",
			errorContains: "parsing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := datasource.New(datasource.TypeArray, "snapshot")
			require.NoError(t, err)
			if tt.fetchInterval != "" {
				ds.AddAnnotation(api.FetchIntervalAnnotation, tt.fetchInterval)
			}
			if tt.timeout != "" {
				ds.AddAnnotation(AnnotationMetricsSnapshotTimeout, tt.timeout)
			}

			timeout, err := snapshotTimeout(ds)
			if tt.errorContains != "" {
				require.ErrorContains(t, err, tt.errorContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, timeout)
		})
	}
}

func TestSnapshotValidation(t *testing.T) {
	tests := []struct {
		name           string
		dataSourceType datasource.Type
		errorContains  string
	}{
		{
			name:           "requires array data source",
			dataSourceType: datasource.TypeSingle,
			errorContains:  "requires an array data source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &otelMetricsOperator{skipListen: true}
			globalParams := apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
			require.NoError(t, o.Init(globalParams))

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			producer := simple.New("producer",
				simple.WithPriority(Priority-1),
				simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
					ds, err := gadgetCtx.RegisterDataSource(tt.dataSourceType, "metrics")
					require.NoError(t, err)
					ds.AddAnnotation(AnnotationMetricsCollect, "true")
					ds.AddAnnotation(AnnotationMetricsSnapshot, "true")
					_, err = ds.AddField("gauge", api.Kind_Uint32, datasource.WithAnnotations(map[string]string{
						AnnotationMetricsType: MetricTypeGauge,
					}))
					return err
				}),
			)
			gadgetCtx := gadgetcontext.New(ctx, "", gadgetcontext.WithDataOperators(o, producer))

			err := gadgetCtx.Run(nil)
			require.ErrorContains(t, err, tt.errorContains)
		})
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
