// Copyright 2022 The Inspektor Gadget authors
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

package integration

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

	// IsCleanup returns true if the step is used to clean resource and
	// should not be skipped even if previous commands failed.
	IsCleanup() bool

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

func WithCbBeforeCleanup(f func(t *testing.T)) func(opts *runTestStepsOpts) {
	return func(ops *runTestStepsOpts) {
		ops.cbBeforeCleanup = f
	}
}

// RunTestSteps is used to run a list of test steps with stopping/clean up logic.
// executeBeforeCleanup is executed before calling the cleanup functions, it can be use for instance
// to print extra logs when the test fails.
func RunTestSteps[S TestStep](steps []S, t *testing.T, options ...Option) {
	opts := &runTestStepsOpts{}

	for _, option := range options {
		option(opts)
	}

	// Defer all cleanup steps so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, o := range steps {
			if o.IsCleanup() {
				o.Run(t)
			}
		}
	}()

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

	// Run all steps except cleanup ones
	for _, step := range steps {
		if step.IsCleanup() {
			continue
		}

		if step.IsStartAndStop() {
			step.Start(t)
			continue
		}

		step.Run(t)
	}
}
