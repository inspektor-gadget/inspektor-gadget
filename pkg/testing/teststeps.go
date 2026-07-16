// Copyright 2019-2024 The Inspektor Gadget authors
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

package testing

import (
	"testing"
	"time"
)

const stepWaitDuration = 10 * time.Second

// TestStep allows combining different steps (e.g command, container creation)
// to allow simplified/consistent flow for tests via RunTestSteps
type TestStep interface {
	// Run runs the step and wait its completion.
	Run(t *testing.T)

	// Start starts the step and immediately returns, it does wait until
	// its completion, use Stop() for that.
	Start(t *testing.T)

	// Stop stops the step and waits its completion.
	Stop(t *testing.T)

	// IsStartAndStop returns true if the step should first be started then
	// stopped after some time.
	IsStartAndStop() bool

	// Running returns true if the step has been started.
	Running() bool
}

type Option func(*runTestStepsOpts)

type runTestStepsOpts struct {
	cbBeforeCleanup func(t *testing.T)
}

// WithCbBeforeCleanup is executed before calling the cleanup functions, it can be use for instance
// to print extra logs when the test fails.
func WithCbBeforeCleanup(f func(t *testing.T)) func(opts *runTestStepsOpts) {
	return func(ops *runTestStepsOpts) {
		ops.cbBeforeCleanup = f
	}
}

// RunTestSteps is used to run a list of test steps with stopping/clean up logic.
func RunTestSteps(steps []TestStep, t *testing.T, options ...Option) {
	opts := &runTestStepsOpts{}

	for _, option := range options {
		option(opts)
	}

	if opts.cbBeforeCleanup != nil {
		defer opts.cbBeforeCleanup(t)
	}

	// Defer stopping commands
	for _, step := range steps {
		step := step
		defer func() {
			if step.IsStartAndStop() && step.Running() {
				// Wait a bit before stopping the step.
				time.Sleep(stepWaitDuration)
				step.Stop(t)
			}
		}()
	}

	// Run or Start all steps
	for _, step := range steps {
		if step.IsStartAndStop() {
			step.Start(t)
			// If the step supports a readiness gate (e.g. a gadget), wait until it is
			// actually capturing before moving on to the next steps (typically the
			// workload). This replaces racy fixed sleeps.
			if rw, ok := step.(readinessWaiter); ok {
				rw.WaitForReady(t)
			}
			continue
		}

		step.Run(t)
	}
}

// readinessWaiter is optionally implemented by TestSteps that can report when they are ready
// (e.g. a gadget that has started capturing). RunTestSteps waits on it after starting such a
// step so subsequent steps only run once the step is ready.
type readinessWaiter interface {
	WaitForReady(t *testing.T)
}
