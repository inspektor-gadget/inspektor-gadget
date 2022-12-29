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

// RunTestSteps is used to run a list of test steps with stopping/clean up logic.
func RunTestSteps[S TestStep](ops []S, t *testing.T) {
	// Defer all cleanup steps so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, o := range ops {
			if o.IsCleanup() {
				o.Run(t)
			}
		}
	}()

	// Defer stopping commands
	for _, cmd := range ops {
		cmd := cmd
		defer func() {
			if cmd.IsStartAndStop() && cmd.Running() {
				// Wait a bit before stopping the step.
				time.Sleep(stepWaitDuration)
				cmd.Stop(t)
			}
		}()
	}

	// Run all steps except cleanup ones
	for _, cmd := range ops {
		if cmd.IsCleanup() {
			continue
		}

		if cmd.IsStartAndStop() {
			cmd.Start(t)
			continue
		}

		cmd.Run(t)
	}
}
