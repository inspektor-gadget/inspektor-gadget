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

package prometheus

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// events that are generated in the test. Counters are incremented based on them and the metric
// configuration
var testEvents = []*stubEvent{
	{Comm: "cat", Uid: 0, IntVal: 105, FloatVal: 201.2},
	{Comm: "cat", Uid: 0, IntVal: 216, FloatVal: 423.3},
	{Comm: "cat", Uid: 1000, IntVal: 327, FloatVal: 645.4},
	{Comm: "ping", Uid: 0, IntVal: 428, FloatVal: 867.5},
	{Comm: "ls", Uid: 1000, IntVal: 429, FloatVal: 1089.6},
}

func TestMetrics(t *testing.T) {
	type testDefinition struct {
		name        string
		config      *Config
		expectedErr bool

		// outer key: metric name, inner key: attributes hash
		expectedInt64Counters   map[string]map[string]int64
		expectedFloat64Counters map[string]map[string]float64
		expectedInt64Gauges     map[string]map[string]int64
		expectedFloat64Gauges   map[string]map[string]float64
	}

	tests := []testDefinition{
		// Generic checks before
		{
			name: "wrong_metric_type",
			config: &Config{
				MetricsName: "wrong_metric_type",
				Metrics: []Metric{
					{
						Name:     "wrong_metric_type",
						Type:     "nonvalidtype",
						Category: "trace",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedErr: true,
		},
		// Wrong configurations
		{
			name: "counter_wrong_gadget_name",
			config: &Config{
				MetricsName: "counter_wrong_gadget_name",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_name",
						Type:     "counter",
						Category: "trace",
						Gadget:   "nonexisting",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_gadget_category",
			config: &Config{
				MetricsName: "counter_wrong_gadget_category",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_category",
						Type:     "counter",
						Category: "nonexisting",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_gadget_type",
			config: &Config{
				MetricsName: "counter_wrong_gadget_type",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_type",
						Type:     "counter",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_type_field",
			config: &Config{
				MetricsName: "counter_wrong_type_field",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_type_field",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "comm",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_selector",
			config: &Config{
				MetricsName: "counter_wrong_selector",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_selector",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "comm",
						Selector: []string{"wrong:cat"},
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_labels",
			config: &Config{
				MetricsName: "counter_wrong_labels",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_labels",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"wrong"},
					},
				},
			},
			expectedErr: true,
		},
		// Check that counters are updated correctly
		{
			name: "counter_no_labels_nor_filtering",
			config: &Config{
				MetricsName: "counter_no_labels_nor_filtering",
				Metrics: []Metric{
					{
						Name:     "counter_no_labels_nor_filtering",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_no_labels_nor_filtering": {"": 5},
			},
		},
		{
			name: "counter_filter_only_root_events",
			config: &Config{
				MetricsName: "counter_filter_only_root_events",
				Metrics: []Metric{
					{
						Name:     "counter_filter_only_root_events",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"uid:0"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_filter_only_root_events": {"": 3},
			},
		},
		{
			name: "counter_filter_only_root_cat_events",
			config: &Config{
				MetricsName: "counter_filter_only_root_cat_events",
				Metrics: []Metric{
					{
						Name:     "counter_filter_only_root_cat_events",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"uid:0", "comm:cat"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_filter_only_root_cat_events": {"": 2},
			},
		},
		{
			name: "counter_filter_uid_greater_than_0",
			config: &Config{
				MetricsName: "counter_filter_uid_greater_than_0",
				Metrics: []Metric{
					{
						Name:     "counter_filter_uid_greater_than_0",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"uid:>0"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_filter_uid_greater_than_0": {"": 2},
			},
		},
		{
			name: "counter_aggregate_by_comm",
			config: &Config{
				MetricsName: "counter_aggregate_by_comm",
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"comm"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_aggregate_by_comm": {"comm=cat,": 3, "comm=ping,": 1, "comm=ls,": 1},
			},
		},
		{
			name: "counter_aggregate_by_uid",
			config: &Config{
				MetricsName: "counter_aggregate_by_uid",
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_uid",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"uid"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_aggregate_by_uid": {"uid=0,": 3, "uid=1000,": 2},
			},
		},
		{
			name: "counter_aggregate_by_uid_and_comm",
			config: &Config{
				MetricsName: "counter_aggregate_by_uid_and_comm",
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_uid_and_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"uid", "comm"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_aggregate_by_uid_and_comm": {
					"comm=cat,uid=0,":    2,
					"comm=cat,uid=1000,": 1,
					"comm=ping,uid=0,":   1,
					"comm=ls,uid=1000,":  1,
				},
			},
		},
		{
			name: "counter_aggregate_by_uid_and_filter_by_comm",
			config: &Config{
				MetricsName: "counter_aggregate_by_uid_and_filter_by_comm",
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_uid_and_filter_by_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"comm:cat"},
						Labels:   []string{"uid"},
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_aggregate_by_uid_and_filter_by_comm": {"uid=0,": 2, "uid=1000,": 1},
			},
		},
		{
			name: "counter_with_int_field",
			config: &Config{
				MetricsName: "counter_with_int_field",
				Metrics: []Metric{
					{
						Name:     "counter_with_int_field",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "intval",
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_with_int_field": {"": 105 + 216 + 327 + 428 + 429},
			},
		},
		{
			name: "counter_with_float_field",
			config: &Config{
				MetricsName: "counter_with_float_field",
				Metrics: []Metric{
					{
						Name:     "counter_with_float_field",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "floatval",
					},
				},
			},
			expectedFloat64Counters: map[string]map[string]float64{
				"counter_with_float_field": {"": 201.2 + 423.3 + 645.4 + 867.5 + 1089.6},
			},
		},
		{
			name: "counter_with_float_field_aggregate_by_uid_and_filter_by_comm",
			config: &Config{
				MetricsName: "counter_with_float_field_aggregate_by_uid_and_filter_by_comm",
				Metrics: []Metric{
					{
						Name:     "counter_with_float_field_aggregate_by_uid_and_filter_by_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "floatval",
						Selector: []string{"comm:cat"},
						Labels:   []string{"uid"},
					},
				},
			},
			expectedFloat64Counters: map[string]map[string]float64{
				"counter_with_float_field_aggregate_by_uid_and_filter_by_comm": {"uid=0,": 201.2 + 423.3, "uid=1000,": 645.4},
			},
		},
		// Multiple counters
		{
			name: "counter_multiple_mixed",
			config: &Config{
				MetricsName: "counter_multiple_mixed",
				Metrics: []Metric{
					{
						Name:     "counter_multiple1",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "floatval",
					},
					{
						Name:     "counter_multiple2",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_multiple2": {"": 5},
			},
			expectedFloat64Counters: map[string]map[string]float64{
				"counter_multiple1": {"": 201.2 + 423.3 + 645.4 + 867.5 + 1089.6},
			},
		},
		// Gauges
		{
			name: "gauge_wrong_gadget_name",
			config: &Config{
				MetricsName: "gauge_wrong_gadget_name",
				Metrics: []Metric{
					{
						Name:     "gauge_wrong_gadget_name",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "nonexisting",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "gauge_wrong_gadget_category",
			config: &Config{
				MetricsName: "gauge_wrong_gadget_category",
				Metrics: []Metric{
					{
						Name:     "gauge_wrong_gadget_category",
						Type:     "gauge",
						Category: "nonexisting",
						Gadget:   "stubsnapshotter",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "gauge_wrong_gadget_type",
			config: &Config{
				MetricsName: "gauge_wrong_gadget_type",
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_type",
						Type:     "gauge",
						Category: "tracer",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "gauge_no_labels_nor_filtering",
			config: &Config{
				MetricsName: "gauge_no_labels_nor_filtering",
				Metrics: []Metric{
					{
						Name:     "gauge_no_labels_nor_filtering",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
					},
				},
			},
			expectedInt64Gauges: map[string]map[string]int64{
				"gauge_no_labels_nor_filtering": {"": 5},
			},
		},
		{
			name: "gauge_filter_only_root_events",
			config: &Config{
				MetricsName: "gauge_filter_only_root_events",
				Metrics: []Metric{
					{
						Name:     "gauge_filter_only_root_events",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
						Selector: []string{"uid:0"},
					},
				},
			},
			expectedInt64Gauges: map[string]map[string]int64{
				"gauge_filter_only_root_events": {"": 3},
			},
		},
		{
			name: "gauge_filter_only_root_cat_events",
			config: &Config{
				MetricsName: "gauge_filter_only_root_cat_events",
				Metrics: []Metric{
					{
						Name:     "gauge_filter_only_root_cat_events",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
						Selector: []string{"uid:0", "comm:cat"},
					},
				},
			},
			expectedInt64Gauges: map[string]map[string]int64{
				"gauge_filter_only_root_cat_events": {"": 2},
			},
		},
		{
			name: "gauge_with_int_field",
			config: &Config{
				MetricsName: "gauge_with_int_field",
				Metrics: []Metric{
					{
						Name:     "gauge_with_int_field",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
						Field:    "intval",
					},
				},
			},
			expectedInt64Gauges: map[string]map[string]int64{
				"gauge_with_int_field": {"": 105 + 216 + 327 + 428 + 429},
			},
		},
		{
			name: "gauge_with_float_field",
			config: &Config{
				MetricsName: "gauge_with_float_field",
				Metrics: []Metric{
					{
						Name:     "gauge_with_float_field",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
						Field:    "floatval",
					},
				},
			},
			expectedFloat64Gauges: map[string]map[string]float64{
				"gauge_with_float_field": {"": 201.2 + 423.3 + 645.4 + 867.5 + 1089.6},
			},
		},
		{
			name: "gauge_multiple",
			config: &Config{
				MetricsName: "gauge_multiple",
				Metrics: []Metric{
					{
						Name:     "gauge_no_labels_nor_filtering",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
					},
					{
						Name:     "gauge_filter_only_root_events",
						Type:     "gauge",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
						Selector: []string{"uid:0"},
					},
				},
			},
			expectedInt64Gauges: map[string]map[string]int64{
				"gauge_no_labels_nor_filtering": {"": 5},
				"gauge_filter_only_root_events": {"": 3},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			wg := &sync.WaitGroup{}
			wg.Add(len(test.config.Metrics))
			ctx = context.WithValue(ctx, valuekey, wg)

			test.config.MetricsName = test.name

			meterProvider := NewStubMeterProvider(t)

			cleanup, err := CreateMetrics(ctx, test.config, meterProvider)
			if test.expectedErr {
				require.Error(t, err)
				return
			}
			require.Nil(t, err)
			t.Cleanup(cleanup)

			name := fmt.Sprintf("gadgets.inspektor-gadget.io/%s", test.config.MetricsName)
			meter := meterProvider.meters[name]

			require.Equal(t, len(test.expectedInt64Counters), len(meter.int64counters))
			require.Equal(t, len(test.expectedFloat64Counters), len(meter.float64counters))
			require.Equal(t, len(test.expectedInt64Gauges), len(meter.int64gauges))

			// Collect metrics: Update gauges
			err = meter.Collect(ctx)
			require.Nil(t, err, "failed to collect metrics")

			// wait for the tracers to run
			err = waitTimeout(wg, 5*time.Second)
			require.Nil(t, err, "waiting timeout: %s", err)

			// int64 counters
			for name, expected := range test.expectedInt64Counters {
				counter, ok := meter.int64counters[name]
				require.True(t, ok, "int64 counter %q not found", name)

				require.Equal(t, expected, counter.values, "counter values are wrong")
			}

			// float64 counters
			for name, expected := range test.expectedFloat64Counters {
				counter, ok := meter.float64counters[name]
				require.True(t, ok, "float64 counter %q not found", name)

				// require.Equal doesn't work because of float comparisons
				require.InDeltaMapValues(t, expected, counter.values, 0.01, "counter values are wrong")
			}

			// int64 gauges
			for name, expected := range test.expectedInt64Gauges {
				gauge, ok := meter.int64gauges[name]
				require.True(t, ok, "int64 gauge %q not found", name)

				require.Equal(t, expected, gauge.values, "counter values are wrong")
			}

			// float64 gauges
			for name, expected := range test.expectedFloat64Gauges {
				gauge, ok := meter.float64gauges[name]
				require.True(t, ok, "float gauge %q not found", name)

				// require.Equal doesn't work because of float comparisons
				require.InDeltaMapValues(t, expected, gauge.values, 0.01, "gauge values are wrong")
			}
		})
	}
}

// Based on https://github.com/embano1/waitgroup/blob/e5229ff7bc061f391c12f2be244bb50f030a6688/waitgroup.go#L27
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) error {
	doneCh := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-timer.C:
		return fmt.Errorf("timed out")
	case <-doneCh:
		return nil
	}
}
