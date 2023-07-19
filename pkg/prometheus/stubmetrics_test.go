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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
)

func NewStubMeterProvider(t *testing.T) *stubMeterProvider {
	return &stubMeterProvider{
		t:      t,
		meters: make(map[string]*stubMeter),
	}
}

type stubMeterProvider struct {
	embedded.MeterProvider
	t      *testing.T
	meters map[string]*stubMeter
}

func (s *stubMeterProvider) Meter(name string, opts ...metric.MeterOption) metric.Meter {
	s.meters[name] = NewStubMeter(s.t)
	return s.meters[name]
}

func NewStubMeter(t *testing.T) *stubMeter {
	return &stubMeter{
		t:                 t,
		int64counters:     make(map[string]*stubInt64Counter),
		float64counters:   make(map[string]*stubFloat64Counter),
		int64gauges:       make(map[string]*stubInt64ObservableGauge),
		float64gauges:     make(map[string]*stubFloat64ObservableGauge),
		int64histograms:   make(map[string]*stubInt64Histogram),
		float64histograms: make(map[string]*stubFloat64Histogram),
	}
}

type stubMeter struct {
	embedded.Meter
	t *testing.T

	int64counters     map[string]*stubInt64Counter
	float64counters   map[string]*stubFloat64Counter
	int64gauges       map[string]*stubInt64ObservableGauge
	float64gauges     map[string]*stubFloat64ObservableGauge
	int64histograms   map[string]*stubInt64Histogram
	float64histograms map[string]*stubFloat64Histogram
	callbacks         []metric.Callback
	mu                sync.Mutex
}

func (s *stubMeter) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &stubInt64Counter{
		values: make(map[string]int64),
	}
	s.int64counters[name] = c
	return c, nil
}

func (s *stubMeter) Int64UpDownCounter(name string, options ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	return nil, nil
}

func (s *stubMeter) Int64Histogram(name string, options ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &stubInt64Histogram{
		values: make(map[string]int64),
	}
	s.int64histograms[name] = c
	return c, nil
}

func (s *stubMeter) Int64ObservableCounter(name string, options ...metric.Int64ObservableCounterOption) (metric.Int64ObservableCounter, error) {
	return nil, nil
}

func (s *stubMeter) Int64ObservableUpDownCounter(name string, options ...metric.Int64ObservableUpDownCounterOption) (metric.Int64ObservableUpDownCounter, error) {
	return nil, nil
}

func (s *stubMeter) Int64ObservableGauge(name string, options ...metric.Int64ObservableGaugeOption) (metric.Int64ObservableGauge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &stubInt64ObservableGauge{
		values: make(map[string]int64),
	}
	s.int64gauges[name] = c
	return c, nil
}

func (s *stubMeter) Float64Counter(name string, options ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &stubFloat64Counter{
		values: make(map[string]float64),
	}
	s.float64counters[name] = c
	return c, nil
}

func (s *stubMeter) Float64UpDownCounter(name string, options ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	return nil, nil
}

func (s *stubMeter) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &stubFloat64Histogram{
		values: make(map[string]float64),
	}
	s.float64histograms[name] = c
	return c, nil
}

func (s *stubMeter) Float64ObservableCounter(name string, options ...metric.Float64ObservableCounterOption) (metric.Float64ObservableCounter, error) {
	return nil, nil
}

func (s *stubMeter) Float64ObservableUpDownCounter(name string, options ...metric.Float64ObservableUpDownCounterOption) (metric.Float64ObservableUpDownCounter, error) {
	return nil, nil
}

func (s *stubMeter) Float64ObservableGauge(name string, options ...metric.Float64ObservableGaugeOption) (metric.Float64ObservableGauge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := &stubFloat64ObservableGauge{
		values: make(map[string]float64),
	}
	s.float64gauges[name] = c
	return c, nil
}

type stubRegistration struct {
	embedded.Registration
}

func (s *stubRegistration) Unregister() error {
	return nil
}

func (s *stubMeter) RegisterCallback(callback metric.Callback, instruments ...metric.Observable) (metric.Registration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.callbacks = append(s.callbacks, callback)

	return &stubRegistration{}, nil
}

// Collect all registered intruments. Only for testing purposes, not part of otel API.
func (s *stubMeter) Collect(ctx context.Context) error {
	obs := &stubObserver{}

	for _, callback := range s.callbacks {
		callback(ctx, obs)
	}

	return nil
}

func attrsToString(kvs []attribute.KeyValue) string {
	ret := ""
	for _, kv := range kvs {
		ret += fmt.Sprintf("%s=%s,", kv.Key, kv.Value.Emit())
	}

	return ret
}

type stubInt64Counter struct {
	embedded.Int64Counter
	values map[string]int64
	mu     sync.Mutex
}

// Add records a change to the counter.
func (c *stubInt64Counter) Add(ctx context.Context, incr int64, options ...metric.AddOption) {
	c.mu.Lock()
	defer c.mu.Unlock()

	attrs := metric.NewAddConfig(options).Attributes()
	c.values[attrsToString(attrs.ToSlice())] += incr
}

type stubFloat64Counter struct {
	embedded.Float64Counter
	values map[string]float64
	mu     sync.Mutex
}

// Add records a change to the counter.
func (c *stubFloat64Counter) Add(ctx context.Context, incr float64, options ...metric.AddOption) {
	c.mu.Lock()
	defer c.mu.Unlock()

	attrs := metric.NewAddConfig(options).Attributes()
	c.values[attrsToString(attrs.ToSlice())] += incr
}

type stubInt64ObservableGauge struct {
	embedded.Int64ObservableGauge
	metric.Int64Observable

	values map[string]int64
	mu     sync.Mutex
}

type stubFloat64ObservableGauge struct {
	embedded.Float64ObservableGauge
	metric.Float64Observable

	values map[string]float64
	mu     sync.Mutex
}

type stubObserver struct {
	embedded.Observer
}

func (o *stubObserver) ObserveFloat64(obsrv metric.Float64Observable, value float64, opts ...metric.ObserveOption) {
	in, ok := obsrv.(*stubFloat64ObservableGauge)
	if !ok {
		panic("bad type passed in")
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	attrs := metric.NewObserveConfig(opts).Attributes()
	in.values[attrsToString(attrs.ToSlice())] = value
}

func (o *stubObserver) ObserveInt64(obsrv metric.Int64Observable, value int64, opts ...metric.ObserveOption) {
	in, ok := obsrv.(*stubInt64ObservableGauge)
	if !ok {
		panic("bad type passed in")
	}

	in.mu.Lock()
	defer in.mu.Unlock()

	attrs := metric.NewObserveConfig(opts).Attributes()
	in.values[attrsToString(attrs.ToSlice())] = value
}

type stubInt64Histogram struct {
	embedded.Int64Histogram
	values map[string]int64
	mu     sync.Mutex
}

// Record records a new measurement in the histogram.
func (h *stubInt64Histogram) Record(ctx context.Context, value int64, options ...metric.RecordOption) {
	h.mu.Lock()
	defer h.mu.Unlock()

	attrs := metric.NewRecordConfig(options).Attributes()
	h.values[attrsToString(attrs.ToSlice())] = value
}

type stubFloat64Histogram struct {
	embedded.Float64Histogram
	values map[string]float64
	mu     sync.Mutex
}

// Record records a new measurement in the histogram.
func (h *stubFloat64Histogram) Record(ctx context.Context, value float64, options ...metric.RecordOption) {
	h.mu.Lock()
	defer h.mu.Unlock()

	attrs := metric.NewRecordConfig(options).Attributes()
	h.values[attrsToString(attrs.ToSlice())] = value
}
