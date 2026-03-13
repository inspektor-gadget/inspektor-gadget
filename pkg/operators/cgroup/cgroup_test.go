// Copyright 2026 The Inspektor Gadget authors
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

package cgroup

import (
	"context"
	"os"
	"path/filepath"
	"sync"
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

// ---------------------------------------------------------------------------
// Parser tests: readCPUStat
// ---------------------------------------------------------------------------

func TestReadCPUStat(t *testing.T) {
	dir := t.TempDir()

	content := `usage_usec 1234567
user_usec 1000000
system_usec 234567
nr_periods 5000
nr_throttled 150
throttled_usec 750000
nr_bursts 0
burst_usec 0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0o644))

	stat, err := readCPUStat(dir)
	require.NoError(t, err)
	assert.Equal(t, uint64(5000), stat.nrPeriods)
	assert.Equal(t, uint64(150), stat.nrThrottled)
	assert.Equal(t, uint64(750000), stat.throttledUsec)
}

func TestReadCPUStatMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := readCPUStat(dir)
	require.Error(t, err)
}

func TestReadCPUStatPartialFields(t *testing.T) {
	dir := t.TempDir()
	// File exists but only has some of the fields we care about
	content := `usage_usec 100
nr_throttled 42
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0o644))

	stat, err := readCPUStat(dir)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), stat.nrPeriods)
	assert.Equal(t, uint64(42), stat.nrThrottled)
	assert.Equal(t, uint64(0), stat.throttledUsec)
}

func TestReadCPUStatMalformedValues(t *testing.T) {
	dir := t.TempDir()
	// Non-numeric values should be silently skipped
	content := `nr_periods notanumber
nr_throttled 10
throttled_usec -5
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0o644))

	stat, err := readCPUStat(dir)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), stat.nrPeriods)
	assert.Equal(t, uint64(10), stat.nrThrottled)
	assert.Equal(t, uint64(0), stat.throttledUsec) // -5 fails ParseUint
}

func TestReadCPUStatEmpty(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(""), 0o644))

	stat, err := readCPUStat(dir)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), stat.nrPeriods)
	assert.Equal(t, uint64(0), stat.nrThrottled)
	assert.Equal(t, uint64(0), stat.throttledUsec)
}

// ---------------------------------------------------------------------------
// Parser tests: readCPUMax
// ---------------------------------------------------------------------------

func TestReadCPUMax(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantQuota  int64
		wantPeriod uint64
		wantErr    bool
	}{
		{
			name:       "limited",
			content:    "50000 100000\n",
			wantQuota:  50000,
			wantPeriod: 100000,
		},
		{
			name:       "unlimited",
			content:    "max 100000\n",
			wantQuota:  -1,
			wantPeriod: 100000,
		},
		{
			name:    "malformed_single_field",
			content: "garbage",
			wantErr: true,
		},
		{
			name:    "malformed_quota_not_number",
			content: "abc 100000\n",
			wantErr: true,
		},
		{
			name:    "malformed_period_not_number",
			content: "50000 xyz\n",
			wantErr: true,
		},
		{
			name:    "empty",
			content: "",
			wantErr: true,
		},
		{
			name:    "three_fields",
			content: "50000 100000 extra\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.max"), []byte(tt.content), 0o644))

			result, err := readCPUMax(dir)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantQuota, result.quota)
			assert.Equal(t, tt.wantPeriod, result.period)
		})
	}
}

func TestReadCPUMaxMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := readCPUMax(dir)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Parser tests: readCPUPressure
// ---------------------------------------------------------------------------

func TestReadCPUPressure(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		dir := t.TempDir()
		content := `some avg10=1.50 avg60=2.30 avg300=0.80 total=12345
full avg10=0.10 avg60=0.20 avg300=0.05 total=678
`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.pressure"), []byte(content), 0o644))

		psi := readCPUPressure(dir)
		assert.True(t, psi.available)
		assert.InDelta(t, 1.50, psi.someAvg10, 0.001)
		assert.InDelta(t, 2.30, psi.someAvg60, 0.001)
	})

	t.Run("missing", func(t *testing.T) {
		dir := t.TempDir()
		psi := readCPUPressure(dir)
		assert.False(t, psi.available)
	})

	t.Run("no_some_line", func(t *testing.T) {
		dir := t.TempDir()
		content := `full avg10=0.10 avg60=0.20 avg300=0.05 total=678
`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.pressure"), []byte(content), 0o644))

		psi := readCPUPressure(dir)
		assert.False(t, psi.available)
		assert.Equal(t, float64(0), psi.someAvg10)
		assert.Equal(t, float64(0), psi.someAvg60)
	})

	t.Run("empty_file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cpu.pressure"), []byte(""), 0o644))

		psi := readCPUPressure(dir)
		assert.False(t, psi.available)
		assert.Equal(t, float64(0), psi.someAvg10)
		assert.Equal(t, float64(0), psi.someAvg60)
	})
}

// ---------------------------------------------------------------------------
// Parser tests: parsePSILine
// ---------------------------------------------------------------------------

func TestParsePSILine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantAvg10 float64
		wantAvg60 float64
	}{
		{
			name:      "normal",
			line:      "some avg10=5.25 avg60=3.10 avg300=1.00 total=999",
			wantAvg10: 5.25,
			wantAvg60: 3.10,
		},
		{
			name:      "zeroes",
			line:      "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
			wantAvg10: 0.0,
			wantAvg60: 0.0,
		},
		{
			name:      "high_values",
			line:      "some avg10=99.99 avg60=50.00 avg300=25.00 total=123456789",
			wantAvg10: 99.99,
			wantAvg60: 50.00,
		},
		{
			name:      "empty_line",
			line:      "",
			wantAvg10: 0,
			wantAvg60: 0,
		},
		{
			name:      "no_equals",
			line:      "some avg10 avg60 avg300 total",
			wantAvg10: 0,
			wantAvg60: 0,
		},
		{
			name:      "malformed_values",
			line:      "some avg10=abc avg60=def avg300=ghi total=jkl",
			wantAvg10: 0,
			wantAvg60: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avg10, avg60 := parsePSILine(tt.line)
			assert.InDelta(t, tt.wantAvg10, avg10, 0.001)
			assert.InDelta(t, tt.wantAvg60, avg60, 0.001)
		})
	}
}

// ---------------------------------------------------------------------------
// Operator lifecycle tests
// ---------------------------------------------------------------------------

func TestCgroupOperatorDisabled(t *testing.T) {
	config := viper.New()
	config.Set(configKeyEnabled, false)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	setupOp := simple.New("setup",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			gadgetCtx.SetVar("config", config)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			ds := gadgetCtx.GetDataSources()["cgroups"]
			assert.Nil(t, ds)
			return nil
		}),
	)

	op := &cgroupOperator{}
	gadgetCtx := gadgetcontext.New(ctx, "test", gadgetcontext.WithDataOperators(op, setupOp))

	err := gadgetCtx.Run(api.ParamValues{})
	require.NoError(t, err)
}

type testSubscriber struct {
	mu     sync.Mutex
	events []datasource.Data
}

func (s *testSubscriber) handleEvent(ds datasource.DataSource, data datasource.Data) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, data)
	return nil
}

func (s *testSubscriber) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// ---------------------------------------------------------------------------
// Delta computation and emission tests using a fake discoverer
// ---------------------------------------------------------------------------

// fakeDiscoverer returns a sequence of cgroupInfo slices, one per call.
type fakeDiscoverer struct {
	mu       sync.Mutex
	calls    int
	sequence [][]cgroupInfo
}

func (f *fakeDiscoverer) discover(_ operators.GadgetContext) ([]cgroupInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.calls
	f.calls++
	if idx >= len(f.sequence) {
		return nil, nil
	}
	return f.sequence[idx], nil
}

func (f *fakeDiscoverer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// runWithFakeDiscoverer creates a gadget context with the cgroup operator
// configured to use a fake discover function, subscribes to events, and
// runs until the context expires. Returns the collected events.
func runWithFakeDiscoverer(t *testing.T, fake *fakeDiscoverer, interval time.Duration, count int, timeout time.Duration) *testSubscriber {
	t.Helper()

	config := viper.New()
	config.Set(configKeyEnabled, true)
	config.Set(configKeyInterval, interval.String())
	if count > 0 {
		config.Set(configKeyCount, count)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	subscriber := &testSubscriber{events: make([]datasource.Data, 0)}

	setupOp := simple.New("setup",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			gadgetCtx.SetVar("config", config)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			ds := gadgetCtx.GetDataSources()["cgroups"]
			require.NotNil(t, ds)
			return ds.Subscribe(subscriber.handleEvent, Priority+1)
		}),
	)

	// Swap the package-level discover function for the fake, restore after test.
	old := discoverCgroupsFn
	discoverCgroupsFn = fake.discover
	t.Cleanup(func() { discoverCgroupsFn = old })

	op := &cgroupOperator{}
	gadgetCtx := gadgetcontext.New(ctx, "test", gadgetcontext.WithDataOperators(op, setupOp))
	err := gadgetCtx.Run(api.ParamValues{})
	require.NoError(t, err)

	return subscriber
}

func TestDeltaComputationBasic(t *testing.T) {
	// Two collection rounds: first establishes baseline (no emit), second emits deltas.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: baseline
			{
				{
					cgroupPath: "/sys/fs/cgroup/test",
					stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 5000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
			},
			// Round 1: cumulative values increased
			{
				{
					cgroupPath: "/sys/fs/cgroup/test",
					stat:       cpuStat{nrPeriods: 200, nrThrottled: 30, throttledUsec: 15000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
			},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)

	// We should have received exactly 1 emission (count=1 means 1 tick after baseline).
	require.Equal(t, 1, subscriber.count())
}

func TestDeltaComputationInactiveCgroupsFiltered(t *testing.T) {
	// Cgroups with zero delta in both nrPeriods and nrThrottled should be filtered out.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: baseline
			{
				{
					cgroupPath: "/sys/fs/cgroup/active",
					stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 5000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
				{
					cgroupPath: "/sys/fs/cgroup/inactive",
					stat:       cpuStat{nrPeriods: 50, nrThrottled: 0, throttledUsec: 0},
					max:        cpuMax{quota: 30000, period: 100000},
				},
			},
			// Round 1: only "active" has new activity; "inactive" is unchanged
			{
				{
					cgroupPath: "/sys/fs/cgroup/active",
					stat:       cpuStat{nrPeriods: 200, nrThrottled: 20, throttledUsec: 10000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
				{
					cgroupPath: "/sys/fs/cgroup/inactive",
					stat:       cpuStat{nrPeriods: 50, nrThrottled: 0, throttledUsec: 0},
					max:        cpuMax{quota: 30000, period: 100000},
				},
			},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// Only the active cgroup should produce a row in the emitted packet.
	require.Equal(t, 1, subscriber.count())
}

func TestCountLimitsEmissions(t *testing.T) {
	// With count=3 and constant activity, we should get exactly 3 emissions.
	makeCgroups := func() []cgroupInfo {
		return []cgroupInfo{
			{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 5000},
				max:        cpuMax{quota: 50000, period: 100000},
			},
		}
	}

	fake := &fakeDiscoverer{
		sequence: func() [][]cgroupInfo {
			// Generate enough rounds: 1 baseline + 3 counted ticks + extra
			rounds := make([][]cgroupInfo, 10)
			for i := range rounds {
				infos := makeCgroups()
				// Make counters increase each round so delta > 0
				infos[0].stat.nrPeriods = uint64(100 * (i + 1))
				infos[0].stat.nrThrottled = uint64(10 * (i + 1))
				infos[0].stat.throttledUsec = uint64(5000 * (i + 1))
				rounds[i] = infos
			}
			return rounds
		}(),
	}
	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 3, 50*time.Millisecond)

	// Should get exactly 3 emissions (count=3 stops the monitor loop after 3 ticks).
	require.Equal(t, 3, subscriber.count())
}

func TestNoBaselineEmission(t *testing.T) {
	// First call to collectAndEmit should NOT emit (emit=false). Even with
	// active cgroups, the baseline collection is silent.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: baseline — active cgroup, but should not emit
			{
				{
					cgroupPath: "/sys/fs/cgroup/test",
					stat:       cpuStat{nrPeriods: 500, nrThrottled: 100, throttledUsec: 99999},
					max:        cpuMax{quota: 10000, period: 100000},
				},
			},
			// Round 1: same values as baseline — delta is 0, so nothing emitted
			{
				{
					cgroupPath: "/sys/fs/cgroup/test",
					stat:       cpuStat{nrPeriods: 500, nrThrottled: 100, throttledUsec: 99999},
					max:        cpuMax{quota: 10000, period: 100000},
				},
			},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// Delta is zero between rounds, so the subscriber receives no data rows.
	require.Equal(t, 0, subscriber.count())
}

func TestEmptyDiscovery(t *testing.T) {
	// If no cgroups are discovered, the operator should run without errors.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			{}, // empty
			{}, // empty
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// No cgroups discovered, so subscriber receives no data rows.
	require.Equal(t, 0, subscriber.count())
}

func TestMultipleCgroupsDeltaComputation(t *testing.T) {
	// Test that deltas are computed independently per cgroup path.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: baseline with two cgroups
			{
				{
					cgroupPath: "/sys/fs/cgroup/web",
					stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 1000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
				{
					cgroupPath: "/sys/fs/cgroup/worker",
					stat:       cpuStat{nrPeriods: 200, nrThrottled: 50, throttledUsec: 8000},
					max:        cpuMax{quota: 25000, period: 100000},
				},
			},
			// Round 1: both advance by different amounts
			{
				{
					cgroupPath: "/sys/fs/cgroup/web",
					stat:       cpuStat{nrPeriods: 150, nrThrottled: 15, throttledUsec: 2000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
				{
					cgroupPath: "/sys/fs/cgroup/worker",
					stat:       cpuStat{nrPeriods: 400, nrThrottled: 150, throttledUsec: 30000},
					max:        cpuMax{quota: 25000, period: 100000},
				},
			},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// Both cgroups had activity, so the subscriber receives 2 data rows.
	require.Equal(t, 2, subscriber.count())
}

func TestNewCgroupAppearsAfterBaseline(t *testing.T) {
	// A cgroup that wasn't in the baseline should use its full cumulative
	// values as the delta (since there's no previous state).
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: only cgroup A
			{
				{
					cgroupPath: "/sys/fs/cgroup/a",
					stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 1000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
			},
			// Round 1: cgroup A + new cgroup B
			{
				{
					cgroupPath: "/sys/fs/cgroup/a",
					stat:       cpuStat{nrPeriods: 200, nrThrottled: 20, throttledUsec: 2000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
				{
					cgroupPath: "/sys/fs/cgroup/b",
					stat:       cpuStat{nrPeriods: 50, nrThrottled: 5, throttledUsec: 500},
					max:        cpuMax{quota: 30000, period: 100000},
				},
			},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// Both cgroups should appear as separate data rows.
	require.Equal(t, 2, subscriber.count())
}

func TestCgroupDisappearsCleanly(t *testing.T) {
	// A cgroup present in baseline but gone in the next round should not cause errors.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: two cgroups
			{
				{
					cgroupPath: "/sys/fs/cgroup/a",
					stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 1000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
				{
					cgroupPath: "/sys/fs/cgroup/b",
					stat:       cpuStat{nrPeriods: 200, nrThrottled: 20, throttledUsec: 2000},
					max:        cpuMax{quota: 30000, period: 100000},
				},
			},
			// Round 1: only cgroup A remains, B disappeared
			{
				{
					cgroupPath: "/sys/fs/cgroup/a",
					stat:       cpuStat{nrPeriods: 200, nrThrottled: 20, throttledUsec: 2000},
					max:        cpuMax{quota: 50000, period: 100000},
				},
			},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// Should succeed without panics or errors, with only cgroup A in the emission.
	require.Equal(t, 1, subscriber.count())
}

func TestPSIFieldsIncludedWhenAvailable(t *testing.T) {
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Baseline
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 1000},
				max:        cpuMax{quota: 50000, period: 100000},
				psi:        psiMetrics{available: true, someAvg10: 5.5, someAvg60: 3.2},
			}},
			// Round 1
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 200, nrThrottled: 30, throttledUsec: 5000},
				max:        cpuMax{quota: 50000, period: 100000},
				psi:        psiMetrics{available: true, someAvg10: 8.1, someAvg60: 6.0},
			}},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	require.Equal(t, 1, subscriber.count())
}

func TestCounterResetDeltaClampedToZero(t *testing.T) {
	// When a cgroup is destroyed and recreated, cumulative counters may
	// decrease. The operator should clamp each delta to zero rather than
	// wrapping around as a huge uint64.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: baseline with high cumulative values
			{{
				cgroupPath: "/sys/fs/cgroup/reset",
				stat:       cpuStat{nrPeriods: 5000, nrThrottled: 500, throttledUsec: 100000},
				max:        cpuMax{quota: 50000, period: 100000},
			}},
			// Round 1: counters are lower than baseline (cgroup was recycled)
			{{
				cgroupPath: "/sys/fs/cgroup/reset",
				stat:       cpuStat{nrPeriods: 10, nrThrottled: 2, throttledUsec: 300},
				max:        cpuMax{quota: 50000, period: 100000},
			}},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// All deltas are clamped to zero (new < old), so nrPeriods=0 and
	// nrThrottled=0 → the cgroup is filtered as inactive.
	require.Equal(t, 0, subscriber.count())
}

func TestFirstIntervalEmission(t *testing.T) {
	// When firstInterval is set, the operator should emit once after the
	// first-interval timer and then continue with the regular ticker.
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Round 0: baseline
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 1000},
				max:        cpuMax{quota: 50000, period: 100000},
			}},
			// Round 1: first-interval emission
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 150, nrThrottled: 20, throttledUsec: 3000},
				max:        cpuMax{quota: 50000, period: 100000},
			}},
			// Round 2: regular ticker emission
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 250, nrThrottled: 40, throttledUsec: 7000},
				max:        cpuMax{quota: 50000, period: 100000},
			}},
		},
	}

	config := viper.New()
	config.Set(configKeyEnabled, true)
	config.Set(configKeyInterval, (10 * time.Millisecond).String())
	config.Set(configKeyFirstInterval, (5 * time.Millisecond).String())
	config.Set(configKeyCount, 1) // 1 regular tick after the first-interval

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	subscriber := &testSubscriber{events: make([]datasource.Data, 0)}

	setupOp := simple.New("setup",
		simple.WithPriority(Priority-1),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			gadgetCtx.SetVar("config", config)
			return nil
		}),
		simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
			ds := gadgetCtx.GetDataSources()["cgroups"]
			require.NotNil(t, ds)
			return ds.Subscribe(subscriber.handleEvent, Priority+1)
		}),
	)

	old := discoverCgroupsFn
	discoverCgroupsFn = fake.discover
	t.Cleanup(func() { discoverCgroupsFn = old })

	op := &cgroupOperator{}
	gadgetCtx := gadgetcontext.New(ctx, "test", gadgetcontext.WithDataOperators(op, setupOp))
	err := gadgetCtx.Run(api.ParamValues{})
	require.NoError(t, err)

	// Expect 2 emissions: one from first-interval, one from the regular ticker (count=1).
	require.Equal(t, 2, subscriber.count())
}

func TestPSIFieldsGracefulWhenUnavailable(t *testing.T) {
	fake := &fakeDiscoverer{
		sequence: [][]cgroupInfo{
			// Baseline — PSI unavailable
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 100, nrThrottled: 10, throttledUsec: 1000},
				max:        cpuMax{quota: 50000, period: 100000},
				psi:        psiMetrics{available: false},
			}},
			// Round 1 — PSI still unavailable
			{{
				cgroupPath: "/sys/fs/cgroup/test",
				stat:       cpuStat{nrPeriods: 200, nrThrottled: 30, throttledUsec: 5000},
				max:        cpuMax{quota: 50000, period: 100000},
				psi:        psiMetrics{available: false},
			}},
		},
	}

	subscriber := runWithFakeDiscoverer(t, fake, 5*time.Millisecond, 1, 50*time.Millisecond)
	// Should work fine even without PSI data.
	require.Equal(t, 1, subscriber.count())
}
