// Copyright 2019-2021 The Inspektor Gadget authors
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
	"fmt"
	"math/rand"
	"testing"
	"time"
)

const (
	namespaceLabelKey   string = "scope"
	namespaceLabelValue string = "ig-integration-tests"
)

type Command interface {
	Run(*testing.T)
	Start(*testing.T)
	Stop(*testing.T)

	RunWithoutTest() error
	StartWithoutTest() error
	WaitWithoutTest() error
	KillWithoutTest() error

	IsCleanup() bool
	IsStartAndStop() bool
	IsStarted() bool
}

// RunCommands is used to run a list of commands with stopping/clean up logic.
func RunCommands(cmds []Command, t *testing.T) {
	// defer all cleanup commands so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, cmd := range cmds {
			if cmd.IsCleanup() {
				cmd.Run(t)
			}
		}
	}()

	// defer stopping commands
	defer func() {
		for _, cmd := range cmds {
			if cmd.IsStartAndStop() && cmd.IsStarted() {
				// Wait a bit before stopping the command.
				time.Sleep(10 * time.Second)
				cmd.Stop(t)
			}
		}
	}()

	// run all commands but cleanup ones
	for _, cmd := range cmds {
		if cmd.IsCleanup() {
			continue
		}

		cmd.Run(t)
	}
}

// GenerateTestNamespaceName returns a string which can be used as unique
// namespace.
// The returned value is: namespace_parameter-random_integer.
func GenerateTestNamespaceName(namespace string) string {
	return fmt.Sprintf("%s-%d", namespace, rand.Int())
}
