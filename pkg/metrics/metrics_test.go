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

package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
)

// TestProxy tests the Proxy functionality
func TestProxy(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create a counter
	counter, err := proxy.Int64Counter("test_counter")
	require.NoError(t, err)
	require.NotNil(t, counter)

	// Add a value to the counter (should not panic even with no providers)
	counter.Add(context.Background(), 1)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err, "Failed to register provider")

	// Create another counter
	counter2, err := proxy.Int64Counter("test_counter2")
	require.NoError(t, err)
	require.NotNil(t, counter2)

	// Add a value to the counter
	counter2.Add(context.Background(), 2)

	// Check that the counter has metrics for the provider
	c2 := counter2.(*int64Counter)
	require.Len(t, c2.counters, 1)

	// Try to register the same provider again (should fail)
	err = proxy.RegisterProvider(provider)
	require.Error(t, err, "Expected error when registering the same provider twice")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the counter no longer has metrics for the provider
	require.Len(t, c2.counters, 0)

	// Add a value to the counter (should not panic)
	counter2.Add(context.Background(), 3)
}

// TestHistogram tests the histogram functionality
func TestHistogram(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create a histogram
	histogram, err := proxy.Int64Histogram("test_histogram")
	require.NoError(t, err)
	require.NotNil(t, histogram)

	// Record a value to the histogram (should not panic even with no providers)
	histogram.Record(context.Background(), 1)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err)

	// Create another histogram
	histogram2, err := proxy.Int64Histogram("test_histogram2")
	require.NoError(t, err)
	require.NotNil(t, histogram2)

	// Record a value to the histogram
	histogram2.Record(context.Background(), 2)

	// Check that the histogram has metrics for the provider
	h2 := histogram2.(*int64Histogram)
	require.Len(t, h2.histograms, 1, "Expected histogram2 to have 1 histogram")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the histogram no longer has metrics for the provider
	require.Len(t, h2.histograms, 0, "Expected histogram2 to have 0 histograms after unregistering provider")

	// Record a value to the histogram (should not panic)
	histogram2.Record(context.Background(), 3)
}

// TestInt64Counter tests the Int64Counter functionality
func TestInt64Counter(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create a counter
	counter, err := proxy.Int64Counter("test_int64_counter")
	require.NoError(t, err)
	require.NotNil(t, counter)

	// Add a value to the counter (should not panic even with no providers)
	counter.Add(context.Background(), 1)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err)

	// Create another counter
	counter2, err := proxy.Int64Counter("test_int64_counter2")
	require.NoError(t, err)
	require.NotNil(t, counter2)

	// Add a value to the counter
	counter2.Add(context.Background(), 2)

	// Check that the counter has metrics for the provider
	c2 := counter2.(*int64Counter)
	require.Len(t, c2.counters, 1, "Expected counter2 to have 1 counter")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the counter no longer has metrics for the provider
	require.Len(t, c2.counters, 0)

	// Add a value to the counter (should not panic)
	counter2.Add(context.Background(), 3)
}

// TestFloat64Counter tests the Float64Counter functionality
func TestFloat64Counter(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create a counter
	counter, err := proxy.Float64Counter("test_float64_counter")
	require.NoError(t, err)
	require.NotNil(t, counter)

	// Add a value to the counter (should not panic even with no providers)
	counter.Add(context.Background(), 1.5)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err)

	// Create another counter
	counter2, err := proxy.Float64Counter("test_float64_counter2")
	require.NoError(t, err)
	require.NotNil(t, counter2)

	// Add a value to the counter
	counter2.Add(context.Background(), 2.5)

	// Check that the counter has metrics for the provider
	c2 := counter2.(*float64Counter)
	require.Len(t, c2.counters, 1, "Expected counter2 to have 1 counter")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the counter no longer has metrics for the provider
	require.Len(t, c2.counters, 0)

	// Add a value to the counter (should not panic)
	counter2.Add(context.Background(), 3.5)
}

// TestInt64Gauge tests the Int64Gauge functionality
func TestInt64Gauge(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create a gauge
	gauge, err := proxy.Int64Gauge("test_int64_gauge")
	require.NoError(t, err)
	require.NotNil(t, gauge)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err)

	// Create another gauge
	gauge2, err := proxy.Int64Gauge("test_int64_gauge2")
	require.NoError(t, err)
	require.NotNil(t, gauge2)

	// Check that the gauge has metrics for the provider
	g2 := gauge2.(*int64Gauge)
	require.Len(t, g2.gauges, 1, "Expected gauge2 to have 1 gauge")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the gauge no longer has metrics for the provider
	require.Len(t, g2.gauges, 0, "Expected gauge2 to have 0 gauges after unregistering provider")
}

// TestFloat64Gauge tests the Float64Gauge functionality
func TestFloat64Gauge(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create a gauge
	gauge, err := proxy.Float64Gauge("test_float64_gauge")
	require.NoError(t, err)
	require.NotNil(t, gauge)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err)

	// Create another gauge
	gauge2, err := proxy.Float64Gauge("test_float64_gauge2")
	require.NoError(t, err)
	require.NotNil(t, gauge2)

	// Check that the gauge has metrics for the provider
	g2 := gauge2.(*float64Gauge)
	require.Len(t, g2.gauges, 1, "Expected gauge2 to have 1 gauge")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the gauge no longer has metrics for the provider
	require.Len(t, g2.gauges, 0, "Expected gauge2 to have 0 gauges after unregistering provider")
}

// TestUpDownCounter tests the updown counter functionality
func TestUpDownCounter(t *testing.T) {
	// Get the proxy
	proxy := global()

	// Create an updown counter
	counter, err := proxy.Int64UpDownCounter("test_updown_counter")
	require.NoError(t, err)
	require.NotNil(t, counter)

	// Add a value to the counter (should not panic even with no providers)
	counter.Add(context.Background(), 1)

	// Register a provider
	provider := noop.NewMeterProvider()
	err = proxy.RegisterProvider(provider)
	require.NoError(t, err)

	// Create another updown counter
	counter2, err := proxy.Int64UpDownCounter("test_updown_counter2")
	require.NoError(t, err)
	require.NotNil(t, counter2)

	// Add a value to the counter
	counter2.Add(context.Background(), 2)

	// Check that the counter has metrics for the provider
	c2 := counter2.(*int64UpDownCounter)
	require.Len(t, c2.counters, 1, "Expected counter2 to have 1 counter")

	// Unregister the provider
	proxy.UnregisterProvider(provider)

	// Check that the counter no longer has metrics for the provider
	require.Len(t, c2.counters, 0)

	// Add a value to the counter (should not panic)
	counter2.Add(context.Background(), 3)
}
