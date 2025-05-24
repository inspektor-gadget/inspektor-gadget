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

// Package metrics provides a singleton metrics provider that can be used
// throughout the application to register metrics.
//
// This package implements a proxy for the OpenTelemetry metric.Meter interface
// that forwards operations to one or more registered metric.MeterProvider instances.
// It allows registering and unregistering providers at runtime, and ensures that
// all metrics are properly registered with new providers and removed when providers
// are unregistered.
//
// The package supports all standard OpenTelemetry metric types:
// - Int64Counter and Float64Counter
// - Int64Histogram and Float64Histogram
// - Int64Gauge and Float64Gauge
// - Int64UpDownCounter and Float64UpDownCounter
//
// Usage:
//
//	import sdkmetric "go.opentelemetry.io/otel/sdk/metric"
//	...
//
//	// Register a provider
//	provider := sdkmetric.NewMeterProvider(...)
//	err := metrics.RegisterProvider(provider)
//	if err != nil {
//	    // Handle error
//	}
//
//	// Create a counter
//	counter, err := metrics.Int64Counter("my_counter")
//	if err != nil {
//	    // Handle error
//	}
//
//	// Add a value to the counter
//	counter.Add(ctx, 1)
//
//	// Unregister a provider when done
//	metrics.UnregisterProvider(provider)
package metrics

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/metric"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

// Proxy is a singleton that provides access to metrics and forwards
// operations to all registered meter providers. It implements the OpenTelemetry
// metric.Meter interface by proxying operations to the underlying providers.
//
// The Proxy maintains a registry of all metrics that have been created, so that
// when a new provider is registered, all existing metrics can be registered with
// the new provider. When a provider is unregistered, all metrics associated with
// that provider are removed.
//
// Thread safety is ensured by using a read-write mutex for all operations.
type Proxy struct {
	mu sync.RWMutex

	// providers is a map of registered metric.MeterProvider instances to their meters
	providers map[metric.MeterProvider]metric.Meter

	// registeredMetrics tracks all metrics that have been created, so they can be
	// registered with new providers
	registeredMetrics []metricRegistration

	// Track all created metric wrappers so we can remove provider references when
	// a provider is unregistered
	int64Counters         []*int64Counter
	float64Counters       []*float64Counter
	int64Histograms       []*int64Histogram
	float64Histograms     []*float64Histogram
	int64Gauges           []*int64Gauge
	float64Gauges         []*float64Gauge
	int64UpDownCounters   []*int64UpDownCounter
	float64UpDownCounters []*float64UpDownCounter
}

// metricRegistration represents a metric that has been registered
type metricRegistration struct {
	creator func(provider metric.MeterProvider, meter metric.Meter) error
}

// global is the singleton instance of Proxy
var global = sync.OnceValue(func() *Proxy {
	return &Proxy{
		providers:             make(map[metric.MeterProvider]metric.Meter),
		registeredMetrics:     make([]metricRegistration, 0),
		int64Counters:         make([]*int64Counter, 0),
		float64Counters:       make([]*float64Counter, 0),
		int64Histograms:       make([]*int64Histogram, 0),
		float64Histograms:     make([]*float64Histogram, 0),
		int64Gauges:           make([]*int64Gauge, 0),
		float64Gauges:         make([]*float64Gauge, 0),
		int64UpDownCounters:   make([]*int64UpDownCounter, 0),
		float64UpDownCounters: make([]*float64UpDownCounter, 0),
	}
})

// RegisterProvider registers a new provider with the global instance
func RegisterProvider(provider metric.MeterProvider) error {
	return global().RegisterProvider(provider)
}

// UnregisterProvider unregisters a provider from the global instance
func UnregisterProvider(provider metric.MeterProvider) {
	global().UnregisterProvider(provider)
}

// Int64Counter registers a new counter on the global instance
func Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return global().Int64Counter(name, options...)
}

// Float64Counter registers a new counter on the global instance
func Float64Counter(name string, options ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	return global().Float64Counter(name, options...)
}

// Int64Histogram registers a new histogram on the global instance
func Int64Histogram(name string, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	return global().Int64Histogram(name, options...)
}

// Float64Histogram registers a new histogram on the global instance
func Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	return global().Float64Histogram(name, options...)
}

// Int64Gauge registers a new gauge on the global instance
func Int64Gauge(name string, options ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	return global().Int64Gauge(name, options...)
}

// Float64Gauge registers a new gauge on the global instance
func Float64Gauge(name string, options ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	return global().Float64Gauge(name, options...)
}

// Int64UpDownCounter registers a new updown counter on the global instance
func Int64UpDownCounter(name string, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	return global().Int64UpDownCounter(name, options...)
}

// Float64UpDownCounter registers a new updown counter on the global instance
func Float64UpDownCounter(name string, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	return global().Float64UpDownCounter(name, options...)
}

// RegisterProvider registers a new metric.MeterProvider with the given name
func (r *Proxy) RegisterProvider(provider metric.MeterProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var err error

	if _, ok := r.providers[provider]; ok {
		return fmt.Errorf("metric provider already registered")
	}

	meter := provider.Meter("inspektor-gadget", metric.WithInstrumentationVersion(version.Version().String()))

	r.providers[provider] = meter

	// Register all existing metrics with the new provider
	for _, reg := range r.registeredMetrics {
		err = errors.Join(err, reg.creator(provider, meter))
	}

	return err
}

// UnregisterProvider removes a metric.MeterProvider with the given name
// and removes all meters/metrics associated with it
func (r *Proxy) UnregisterProvider(provider metric.MeterProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove the provider from the map
	delete(r.providers, provider)

	// Remove all metrics associated with this provider
	for _, counter := range r.int64Counters {
		delete(counter.counters, provider)
	}
	for _, counter := range r.float64Counters {
		delete(counter.counters, provider)
	}
	for _, histogram := range r.int64Histograms {
		delete(histogram.histograms, provider)
	}
	for _, histogram := range r.float64Histograms {
		delete(histogram.histograms, provider)
	}
	for _, gauge := range r.int64Gauges {
		delete(gauge.gauges, provider)
	}
	for _, gauge := range r.float64Gauges {
		delete(gauge.gauges, provider)
	}
	for _, counter := range r.int64UpDownCounters {
		delete(counter.counters, provider)
	}
	for _, counter := range r.float64UpDownCounters {
		delete(counter.counters, provider)
	}
}

func (r *Proxy) registerMetrics(creator func(provider metric.MeterProvider, meter metric.Meter) error) error {
	reg := metricRegistration{
		creator: creator,
	}
	r.registeredMetrics = append(r.registeredMetrics, reg)

	var err error
	for provider, meter := range r.providers {
		err = errors.Join(err, reg.creator(provider, meter))
	}
	return err
}

// Int64Counter creates a new Int64Counter and registers it with all providers
func (r *Proxy) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a counter that forwards to all providers
	counter := &int64Counter{
		p:        r,
		counters: make(map[metric.MeterProvider]metric.Int64Counter),
	}

	// Add the counter to the list of counters
	r.int64Counters = append(r.int64Counters, counter)
	return counter, r.registerMetrics(metricCreator(name, metric.Meter.Int64Counter, counter.counters, options...))
}

// Float64Counter creates a new float64Counter and registers it with all providers
func (r *Proxy) Float64Counter(name string, options ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a counter that forwards to all providers
	counter := &float64Counter{
		p:        r,
		counters: make(map[metric.MeterProvider]metric.Float64Counter),
	}

	// Add the counter to the list of counters
	r.float64Counters = append(r.float64Counters, counter)

	return counter, r.registerMetrics(metricCreator(name, metric.Meter.Float64Counter, counter.counters, options...))
}

// Int64Histogram creates a new int64Histogram and registers it with all providers
func (r *Proxy) Int64Histogram(name string, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a histogram that forwards to all providers
	histogram := &int64Histogram{
		p:          r,
		histograms: make(map[metric.MeterProvider]metric.Int64Histogram),
	}

	// Add the histogram to the list of histograms
	r.int64Histograms = append(r.int64Histograms, histogram)
	return histogram, r.registerMetrics(metricCreator(name, metric.Meter.Int64Histogram, histogram.histograms, options...))
}

// Float64Histogram creates a new float64Histogram and registers it with all providers
func (r *Proxy) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a histogram that forwards to all providers
	histogram := &float64Histogram{
		p:          r,
		histograms: make(map[metric.MeterProvider]metric.Float64Histogram),
	}

	// Add the histogram to the list of histograms
	r.float64Histograms = append(r.float64Histograms, histogram)
	return histogram, r.registerMetrics(metricCreator(name, metric.Meter.Float64Histogram, histogram.histograms, options...))
}

// Int64Gauge creates a new Int64Gauge and registers it with all providers
func (r *Proxy) Int64Gauge(name string, options ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a gauge that forwards to all providers
	gauge := &int64Gauge{
		p:      r,
		gauges: make(map[metric.MeterProvider]metric.Int64Gauge),
	}

	// Add the gauge to the list of gauges
	r.int64Gauges = append(r.int64Gauges, gauge)
	return gauge, r.registerMetrics(metricCreator(name, metric.Meter.Int64Gauge, gauge.gauges, options...))
}

// Float64Gauge creates a new Float64Gauge and registers it with all providers
func (r *Proxy) Float64Gauge(name string, options ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a gauge that forwards to all providers
	gauge := &float64Gauge{
		p:      r,
		gauges: make(map[metric.MeterProvider]metric.Float64Gauge),
	}

	// Add the gauge to the list of gauges
	r.float64Gauges = append(r.float64Gauges, gauge)
	return gauge, r.registerMetrics(metricCreator(name, metric.Meter.Float64Gauge, gauge.gauges, options...))
}

// Int64UpDownCounter creates a new Int64UpDownCounter and registers it with all providers
func (r *Proxy) Int64UpDownCounter(name string, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a counter that forwards to all providers
	counter := &int64UpDownCounter{
		p:        r,
		counters: make(map[metric.MeterProvider]metric.Int64UpDownCounter),
	}

	// Add the counter to the list of counters
	r.int64UpDownCounters = append(r.int64UpDownCounters, counter)
	return counter, r.registerMetrics(metricCreator(name, metric.Meter.Int64UpDownCounter, counter.counters, options...))
}

// Float64UpDownCounter creates a new Float64UpDownCounter and registers it with all providers
func (r *Proxy) Float64UpDownCounter(name string, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a counter that forwards to all providers
	counter := &float64UpDownCounter{
		p:        r,
		counters: make(map[metric.MeterProvider]metric.Float64UpDownCounter),
	}

	// Add the counter to the list of counters
	r.float64UpDownCounters = append(r.float64UpDownCounters, counter)
	return counter, r.registerMetrics(metricCreator(name, metric.Meter.Float64UpDownCounter, counter.counters, options...))
}

// int64Counter forwards Add calls to all underlying counters
type int64Counter struct {
	metric.Int64Counter
	p        *Proxy
	counters map[metric.MeterProvider]metric.Int64Counter
}

// Add adds the given value to all underlying counters
func (c *int64Counter) Add(ctx context.Context, value int64, options ...metric.AddOption) {
	c.p.mu.RLock()
	defer c.p.mu.RUnlock()
	for _, counter := range c.counters {
		counter.Add(ctx, value, options...)
	}
}

// float64Counter forwards Add calls to all underlying counters
type float64Counter struct {
	metric.Float64Counter
	p        *Proxy
	counters map[metric.MeterProvider]metric.Float64Counter
}

// Add adds the given value to all underlying counters
func (c *float64Counter) Add(ctx context.Context, value float64, options ...metric.AddOption) {
	c.p.mu.RLock()
	defer c.p.mu.RUnlock()
	for _, counter := range c.counters {
		counter.Add(ctx, value, options...)
	}
}

// int64Histogram forwards Record calls to all underlying histograms
type int64Histogram struct {
	metric.Int64Histogram
	p          *Proxy
	histograms map[metric.MeterProvider]metric.Int64Histogram
}

// Record records the given value to all underlying histograms
func (h *int64Histogram) Record(ctx context.Context, value int64, options ...metric.RecordOption) {
	h.p.mu.RLock()
	defer h.p.mu.RUnlock()
	for _, histogram := range h.histograms {
		histogram.Record(ctx, value, options...)
	}
}

// float64Histogram forwards Record calls to all underlying histograms
type float64Histogram struct {
	metric.Float64Histogram
	p          *Proxy
	histograms map[metric.MeterProvider]metric.Float64Histogram
}

// Record records the given value to all underlying histograms
func (h *float64Histogram) Record(ctx context.Context, value float64, options ...metric.RecordOption) {
	h.p.mu.RLock()
	defer h.p.mu.RUnlock()
	for _, histogram := range h.histograms {
		histogram.Record(ctx, value, options...)
	}
}

// int64Gauge forwards operations to all underlying gauges
type int64Gauge struct {
	metric.Int64Gauge
	p      *Proxy
	gauges map[metric.MeterProvider]metric.Int64Gauge
}

// Add adds the given value to all underlying gauges
func (g *int64Gauge) Add(ctx context.Context, value int64, options ...metric.RecordOption) {
	g.p.mu.RLock()
	defer g.p.mu.RUnlock()
	for _, gauge := range g.gauges {
		gauge.Record(ctx, value, options...)
	}
}

// float64Gauge forwards operations to all underlying gauges
type float64Gauge struct {
	metric.Float64Gauge
	p      *Proxy
	gauges map[metric.MeterProvider]metric.Float64Gauge
}

// Add adds the given value to all underlying gauges
func (g *float64Gauge) Add(ctx context.Context, value float64, options ...metric.RecordOption) {
	g.p.mu.RLock()
	defer g.p.mu.RUnlock()
	for _, gauge := range g.gauges {
		gauge.Record(ctx, value, options...)
	}
}

// int64UpDownCounter forwards Add calls to all underlying updown counters
type int64UpDownCounter struct {
	metric.Int64UpDownCounter
	p        *Proxy
	counters map[metric.MeterProvider]metric.Int64UpDownCounter
}

// Add adds the given value to all underlying updown counters
func (c *int64UpDownCounter) Add(ctx context.Context, value int64, options ...metric.AddOption) {
	c.p.mu.RLock()
	defer c.p.mu.RUnlock()
	for _, counter := range c.counters {
		counter.Add(ctx, value, options...)
	}
}

// float64UpDownCounter forwards Add calls to all underlying updown counters
type float64UpDownCounter struct {
	metric.Float64UpDownCounter
	p        *Proxy
	counters map[metric.MeterProvider]metric.Float64UpDownCounter
}

// Add adds the given value to all underlying updown counters
func (c *float64UpDownCounter) Add(ctx context.Context, value float64, options ...metric.AddOption) {
	c.p.mu.RLock()
	defer c.p.mu.RUnlock()
	for _, counter := range c.counters {
		counter.Add(ctx, value, options...)
	}
}

func metricCreator[T any, U any](
	name string,
	inst func(metric.Meter, string, ...U) (T, error),
	registry map[metric.MeterProvider]T,
	options ...U,
) func(provider metric.MeterProvider, meter metric.Meter) error {
	return func(provider metric.MeterProvider, meter metric.Meter) error {
		m, err := inst(meter, name, options...)
		if err != nil {
			return err
		}
		registry[provider] = m
		return nil
	}
}
