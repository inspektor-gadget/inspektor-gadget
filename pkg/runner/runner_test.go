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

package runner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var expectedEvents = []*types.Event{
	{Message: "event1"},
	{Message: "event2"},
	{Message: "event3"},
	{Message: "event4"},
}

// Implements the Tracer interface for our testing usage
type MocTracer struct {
	events []*types.Event

	sleepDuration time.Duration
	runner        *Runner
}

func NewMocTracer() *MocTracer {
	tracer := &MocTracer{
		events: []*types.Event{},
	}
	return tracer
}

func (t *MocTracer) InitWithGadgetInfo(*types.GadgetInfo) error {
	return nil
}

func (t *MocTracer) RunWithoutGadgetContext(logger logger.Logger, ctx context.Context, timeout time.Duration, params *params.Params) error {
	doneChannel := ctx.Done()

	var timeoutChannel <-chan struct{}
	if timeout > 0 {
		withTimeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
		defer timeoutCancel()
		timeoutChannel = withTimeoutCtx.Done()
	}

	for _, ev := range t.events {
		t.runner.eb.Output(ev.Message)

		select {
		case <-doneChannel:
		case <-timeoutChannel:
			return nil
		case <-time.After(t.sleepDuration):
			continue
		}
	}
	return nil
}

func (t *MocTracer) Close() {
}

func CreateMocTracerAndRunner(opts ...func(*RunnerOpts)) (*MocTracer, *Runner) {
	tracer := NewMocTracer()
	r := newRunnerFromTracer(tracer, opts...)
	tracer.runner = r
	tracer.events = expectedEvents
	return tracer, r
}

func TestNewRunner(t *testing.T) {
	t.Parallel()

	_, r := CreateMocTracerAndRunner()

	assert.Equal(t, RunnerStateNotStarted, r.state)
	assert.NotNil(t, r.tracer)
}

func TestMultipleCloseAfterNew(t *testing.T) {
	t.Parallel()

	_, r := CreateMocTracerAndRunner()

	assert.NoError(t, r.Close())
	assert.Equal(t, RunnerStateCompleted, r.state)
	assert.Nil(t, r.tracer)

	// A second one should also work without errors
	assert.NoError(t, r.Close())
	assert.Equal(t, RunnerStateCompleted, r.state)
	assert.Nil(t, r.tracer)
}

func DrainEvents(t *testing.T, r *Runner, tracer *MocTracer, sleepDuration time.Duration, result *[]string, finishWG *sync.WaitGroup) {
	for !r.Done() {
		event, err := r.GetEvent()
		assert.NoError(t, err)
		*result = append(*result, event)
		time.Sleep(sleepDuration)
	}
	if finishWG != nil {
		finishWG.Done()
	}
}

func CheckEvents(t *testing.T, events []string, expectedEvents []*types.Event) {
	require.Equal(t, len(expectedEvents), len(events))
	for i, e := range expectedEvents {
		assert.Equal(t, e.Message, events[i])
	}
}

func TestGetEventWithoutStarting(t *testing.T) {
	t.Parallel()

	_, r := CreateMocTracerAndRunner()

	event, err := r.GetEvent()
	assert.Equal(t, "", event)
	assert.Equal(t, "runner not started", err.Error())
}

func TestGetEvents(t *testing.T) {
	t.Parallel()

	tracer, r := CreateMocTracerAndRunner()
	assert.NoError(t, r.Run())
	events := []string{}
	DrainEvents(t, r, tracer, 0, &events, nil)

	assert.NoError(t, r.WaitForAllEvents())
	assert.NoError(t, r.Close())

	CheckEvents(t, events, expectedEvents)
}

func TestGetEventsInGoRoutine(t *testing.T) {
	t.Parallel()

	tracer, r := CreateMocTracerAndRunner()
	assert.NoError(t, r.Run())
	events := []string{}
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	go DrainEvents(t, r, tracer, 0, &events, finishWG)

	assert.NoError(t, r.WaitForAllEvents())
	assert.NoError(t, r.Close())

	finishWG.Wait()
	CheckEvents(t, events, expectedEvents)
}

func TestGetEventsProducerSleep(t *testing.T) {
	t.Parallel()

	tracer, r := CreateMocTracerAndRunner()
	tracer.sleepDuration = 100 * time.Millisecond
	assert.NoError(t, r.Run())
	events := []string{}
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	go DrainEvents(t, r, tracer, 0, &events, finishWG)

	assert.NoError(t, r.WaitForAllEvents())
	assert.NoError(t, r.Close())

	finishWG.Wait()
	CheckEvents(t, events, expectedEvents)
}

func TestGetEventsConsumerSleep(t *testing.T) {
	t.Parallel()

	tracer, r := CreateMocTracerAndRunner()
	assert.NoError(t, r.Run())
	events := []string{}
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	go DrainEvents(t, r, tracer, 100*time.Millisecond, &events, finishWG)

	assert.NoError(t, r.WaitForAllEvents())
	assert.NoError(t, r.Close())

	finishWG.Wait()
	CheckEvents(t, events, expectedEvents)
}

func TestGetEventsProducerConsumerSleep(t *testing.T) {
	t.Parallel()

	tracer, r := CreateMocTracerAndRunner()
	tracer.sleepDuration = 100 * time.Millisecond
	assert.NoError(t, r.Run())
	events := []string{}
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	go DrainEvents(t, r, tracer, 0, &events, finishWG)

	assert.NoError(t, r.WaitForAllEvents())
	assert.NoError(t, r.Close())

	finishWG.Wait()
	CheckEvents(t, events, expectedEvents)
}

func TestRunnerTimeout(t *testing.T) {
	// Not using t.Parallel() to make sure the timeout is not hit because of not running
	// If the task gets flaky remove it
	t.Parallel()

	timeout := 2 * time.Second
	sleepDuration := 3 * time.Second

	tracer, r := CreateMocTracerAndRunner(WithTimeout(timeout))
	tracer.events = tracer.events[:1]
	tracer.sleepDuration = sleepDuration

	startTime := time.Now()
	require.NoError(t, r.Run())
	assert.NoError(t, r.Wait())
	elapsed := time.Since(startTime)
	assert.Greater(t, elapsed, timeout, "The timeout was not respected")
	assert.Less(t, elapsed, sleepDuration, "The timeout was not respected")
	assert.NoError(t, r.Close())
}

func TestRunnerContext(t *testing.T) {
	// Not using t.Parallel() to make sure the timeout is not hit because of not running
	// If the task gets flaky remove it
	t.Parallel()
	ctx, ctxCancel := context.WithCancel(context.Background())

	timeout := 3 * time.Second

	tracer, r := CreateMocTracerAndRunner(WithContext(ctx), WithTimeout(timeout))
	tracer.events = tracer.events[:1]
	tracer.sleepDuration = 4 * time.Second

	startTime := time.Now()
	require.NoError(t, r.Run())
	ctxCancel()
	assert.NoError(t, r.Wait())
	elapsed := time.Since(startTime)
	assert.NoError(t, r.Close())
	assert.Less(t, elapsed, timeout, "The context cancelation was not respected")
}

func TestWait(t *testing.T) {
	t.Parallel()
	_, r := CreateMocTracerAndRunner()
	require.NoError(t, r.Run())
	// Make sure the events are currently in the buffer
	time.Sleep(100 * time.Millisecond)
	// Wait should return even if there are currently 4 events in the buffer
	assert.NoError(t, r.Wait())
	assert.NoError(t, r.Close())
}

func TestWaitForAllEvents(t *testing.T) {
	// Not using t.Parallel() to make sure the time calculation is not affected by parallelism
	// If the task gets flaky remove it
	t.Parallel()
	tracer, r := CreateMocTracerAndRunner()
	require.NoError(t, r.Run())

	drainSleepTime := 100 * time.Millisecond

	startTime := time.Now()
	events := []string{}
	finishWG := &sync.WaitGroup{}
	finishWG.Add(1)
	go DrainEvents(t, r, tracer, drainSleepTime, &events, finishWG)
	// WaitForAllEvents should return only after all events are consumed
	assert.NoError(t, r.WaitForAllEvents())
	elapsed := time.Since(startTime)
	assert.NoError(t, r.Close())

	finishWG.Wait()
	assert.Greater(t, elapsed, drainSleepTime*time.Duration(len(events)-1), "WaitForAllEvents did not wait for all events to be captured")
	CheckEvents(t, events, expectedEvents)
}

func TestGetEventsAndCloseWithoutWait(t *testing.T) {
	t.Parallel()

	tracer, r := CreateMocTracerAndRunner()
	assert.NoError(t, r.Run())
	events := []string{}
	DrainEvents(t, r, tracer, 0, &events, nil)

	assert.NoError(t, r.Close())

	CheckEvents(t, events, expectedEvents)
}
