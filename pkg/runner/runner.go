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
	"fmt"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type runnerState string

const (
	RunnerStateNotStarted runnerState = "not-started"
	RunnerStateStarted    runnerState = "started"
	RunnerStateCompleted  runnerState = "completed"

	poisonPill = ""
)

type RunnerOpts struct {
	tracer.RunOpts

	Timeout    time.Duration
	context    context.Context
	ebpfParams map[string]types.EBPFParam
}

// WithTimeout sets the timeout for the gadget
func WithTimeout(timeout time.Duration) func(*RunnerOpts) {
	return func(r *RunnerOpts) {
		r.Timeout = timeout
	}
}

// WithContext sets the context for the gadget
// It is useful if one wants to cancel the gadget execution
func WithContext(ctx context.Context) func(*RunnerOpts) {
	return func(r *RunnerOpts) {
		r.context = ctx
	}
}

// WithValidateMetadata sets whether the metadata should be validated against the eBPF program
func WithValidateMetadata(validateMetadata bool) func(*RunnerOpts) {
	return func(r *RunnerOpts) {
		r.ValidateMetadata = validateMetadata
	}
}

// WithPullPolicy sets the pull policy for pulling the gadget image
func WithPullPolicy(pullPolicy string) func(*RunnerOpts) {
	return func(r *RunnerOpts) {
		r.PullPolicy = pullPolicy
	}
}

// WithAuthOpts sets the authentication options when pulling the gadget image
func WithAuthOpts(authOpts *oci.AuthOptions) func(*RunnerOpts) {
	return func(r *RunnerOpts) {
		r.AuthOpts = authOpts
	}
}

type Runner struct {
	// Named to hide its methods from the public API
	eb eventBuffer

	runnerOpts RunnerOpts
	tracer     tracerInterface

	state      runnerState
	stateMutex sync.Mutex
	stateCV    *sync.Cond
}

// eventBuffer implements the logger.Logger interface
type eventBuffer struct {
	// TODO: buffersize/maxsize?
	buffer     []string
	eventMutex sync.Mutex
	eventCV    *sync.Cond
}

func (r *eventBuffer) Output(payload string) {
	r.eventMutex.Lock()
	defer r.eventMutex.Unlock()
	r.buffer = append(r.buffer, payload)
	r.eventCV.Broadcast()
}

func (r *eventBuffer) Logf(severity logger.Level, fmtStr string, params ...any) {
	fmt.Printf(fmtStr, params...)
}

type tracerInterface interface {
	InitWithGadgetInfo(*types.GadgetInfo) error
	RunWithoutGadgetContext(logger logger.Logger, ctx context.Context, timeout time.Duration, params *params.Params) error
	Close()
}

// NewRunner creates a new runner with the given image and options
func NewRunner(image string, opts ...func(*RunnerOpts)) (*Runner, error) {
	return newRunner(image, opts...)
}

// NewRunnerFromBytes creates a new runner with the given eBPF program bytes and options
// The Metadata will be inferred from the eBPF program
func NewRunnerFromBytes(ebpfBytes []byte, opts ...func(*RunnerOpts)) (*Runner, error) {
	return newRunner(ebpfBytes, opts...)
}

func newRunner(program any, opts ...func(*RunnerOpts)) (*Runner, error) {
	gadgetDesc := tracer.GadgetDesc{}
	runGadget, err := gadgetDesc.NewInstance()
	if err != nil {
		return nil, fmt.Errorf("creating run gadgetDesc instance: %w", err)
	}
	tracerInstance := runGadget.(*tracer.Tracer)

	r := newRunnerFromTracer(tracerInstance, opts...)

	gadgetInfo, err := getGadgetInfo(program, &gadgetDesc, &r.runnerOpts)
	if err != nil {
		return nil, err
	}

	err = r.tracer.InitWithGadgetInfo(gadgetInfo)
	if err != nil {
		return nil, fmt.Errorf("initializing run gadget: %w", err)
	}

	// TODO: Add functions to set the params
	r.runnerOpts.ebpfParams = gadgetInfo.GadgetMetadata.EBPFParams

	// Set Event Handler
	conv := gadgetDesc.JSONConverter(gadgetInfo, &r.eb)
	tracerInstance.SetEventHandler(func(ev *types.Event) {
		conv(ev)
	})
	tracerInstance.SetEventHandlerArray(func(ev []*types.Event) {
		conv(ev)
	})

	return r, nil
}

func getGadgetInfo(program any, gadgetDesc *tracer.GadgetDesc, RunnerOpts *RunnerOpts) (*types.GadgetInfo, error) {
	switch p := program.(type) {
	case string:
		gadgetInfo, err := gadgetDesc.GetGadgetInfoWithRunOpts(p, RunnerOpts.RunOpts, logger.DefaultLogger())
		if err != nil {
			return nil, fmt.Errorf("getting gadget info: %w", err)
		}
		return gadgetInfo, nil
	case []byte:
		gadgetInfo, err := gadgetDesc.GetGadgetInfoFromBytesRunOpts(p, RunnerOpts.RunOpts, logger.DefaultLogger())
		if err != nil {
			return nil, fmt.Errorf("getting gadget info: %w", err)
		}
		return gadgetInfo, nil
	default:
		return nil, fmt.Errorf("invalid program type")
	}
}

func newRunnerFromTracer(t tracerInterface, opts ...func(*RunnerOpts)) *Runner {
	r := &Runner{
		tracer: t,
		runnerOpts: RunnerOpts{
			RunOpts: tracer.RunOpts{
				ValidateMetadata: true,
				PullPolicy:       oci.PullImageMissing,
				AuthOpts: &oci.AuthOptions{
					AuthFile: oci.DefaultAuthFile,
				},
			},
			Timeout: 0,
			context: context.Background(),
		},
		state:      RunnerStateNotStarted,
		stateMutex: sync.Mutex{},

		eb: eventBuffer{
			buffer:     []string{},
			eventMutex: sync.Mutex{},
		},
	}
	r.stateCV = sync.NewCond(&r.stateMutex)
	r.eb.eventCV = sync.NewCond(&r.eb.eventMutex)

	for _, opt := range opts {
		opt(&r.runnerOpts)
	}

	return r
}

// Run starts the gadget in the background
func (r *Runner) Run() error {
	r.stateMutex.Lock()
	defer r.stateMutex.Unlock()
	if r.state != RunnerStateNotStarted {
		return fmt.Errorf("runner already started")
	}
	r.state = RunnerStateStarted

	// TODO: eBPF gadget parameters
	go func() {
		ebpfParams := params.Params{}
		for _, v := range r.runnerOpts.ebpfParams {
			// Make a copy
			ebpfParam := v
			ebpfParams.Add(ebpfParam.ToParam())
		}

		err := r.tracer.RunWithoutGadgetContext(logger.DefaultLogger(), r.runnerOpts.context, r.runnerOpts.Timeout, &ebpfParams)
		if err != nil {
			fmt.Printf("Run the gadget: %v\n", err)
		}

		r.eb.eventMutex.Lock()
		r.eb.buffer = append(r.eb.buffer, poisonPill)
		r.eb.eventCV.Broadcast()
		r.eb.eventMutex.Unlock()

		r.stateMutex.Lock()
		if r.state == RunnerStateStarted {
			r.tracer.Close()
		}
		r.state = RunnerStateCompleted
		r.stateCV.Broadcast()
		r.stateMutex.Unlock()
	}()

	return nil
}

// GetEvent returns the next event from the gadget
// If the runner has not started, it will return an error
// If there are no events, it will block until an event is available
// If the runner has completed and there are no remaining events in the buffer, it will return an error
func (r *Runner) GetEvent() (string, error) {
	r.stateMutex.Lock()
	if r.state == RunnerStateNotStarted {
		r.stateMutex.Unlock()
		return "", fmt.Errorf("runner not started")
	}
	r.stateMutex.Unlock()

	r.eb.eventMutex.Lock()
	defer r.eb.eventMutex.Unlock()
	for len(r.eb.buffer) == 0 {
		r.eb.eventCV.Wait()
	}
	event := r.eb.buffer[0]
	if event == poisonPill {
		return "", fmt.Errorf("buffer is empty and the runner has completed")
	}
	r.eb.buffer = r.eb.buffer[1:]
	return event, nil
}

// Done returns true if the runner has completed and there are no remaining events in the buffer
// Otherwise it blocks until a new event is available and returns false
func (r *Runner) Done() bool {
	r.eb.eventMutex.Lock()
	defer r.eb.eventMutex.Unlock()

	for len(r.eb.buffer) == 0 {
		r.eb.eventCV.Wait()
	}
	return r.eb.buffer[0] == poisonPill
}

// Wait blocks and returns as soon as the gadget completed its operation
func (r *Runner) Wait() error {
	// Is an error return still needed?
	r.stateMutex.Lock()

	for r.state != RunnerStateCompleted {
		r.stateCV.Wait()
	}
	r.stateMutex.Unlock()
	return nil
}

// WaitForAllEvents blocks until the gadget completed its operation and all events have been read
func (r *Runner) WaitForAllEvents() error {
	err := r.Wait()
	if err != nil {
		return err
	}

	r.eb.eventMutex.Lock()
	defer r.eb.eventMutex.Unlock()
	for {
		for len(r.eb.buffer) == 0 {
			r.eb.eventCV.Wait()
		}

		if r.eb.buffer[0] == poisonPill {
			return nil
		}
		// It wasn't the poison pill
		// Unlock and Lock the mutex to give other goroutines a chance to read and remove events
		r.eb.eventMutex.Unlock()
		r.eb.eventMutex.Lock()
	}
}

// Close cleans up the resources
func (r *Runner) Close() error {
	r.stateMutex.Lock()
	defer r.stateMutex.Unlock()

	if r.state == RunnerStateStarted {
		r.tracer.Close()
		r.eb.eventMutex.Lock()
		r.eb.buffer = append(r.eb.buffer, poisonPill)
		r.eb.eventCV.Broadcast()
		r.eb.eventMutex.Unlock()
	}
	r.state = RunnerStateCompleted
	r.tracer = nil
	return nil
}
