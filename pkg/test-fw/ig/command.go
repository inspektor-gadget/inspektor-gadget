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

package ig

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

type Command struct {
	// IG wrapper
	IG

	// Name of the command to be run, used to give information.
	Name string

	// ExpectedString contains the exact expected output of the command.
	ExpectedString string

	// ExpectedRegexp contains a regex used to match against the command output.
	ExpectedRegexp string

	// ValidateOutput is a function used to verify the output. It must make the test fail in
	// case of error.
	ValidateOutput func(t *testing.T, output string)
}

// verifyOutput verifies if the stdout match with the expected regular expression and the expected
// string. If it doesn't, verifyOutput makes the test fail.
func (c *Command) verifyOutput(t *testing.T) {
	output := c.stdout.String()

	if c.ExpectedRegexp != "" {
		r := regexp.MustCompile(c.ExpectedRegexp)
		if !r.MatchString(output) {
			t.Fatalf("output didn't match the expected regexp: %s", c.ExpectedRegexp)
		}
	}

	if c.ExpectedString != "" {
		require.Equal(t, c.ExpectedString, output, "output didn't match the expected string")
	}

	if c.ValidateOutput != nil {
		c.ValidateOutput(t, output)
	}
}

// Run runs the Command on the given as parameter test.
func (c *Command) Run(t *testing.T) {
	t.Logf("Run command(%s):\n", c.Name)
	err := c.run()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())
	require.NoError(t, err, "failed to run command(%s)", c.Name)

	c.verifyOutput(t)
}

// Start starts the Command on the given as parameter test, you need to
// wait it using Stop().
func (c *Command) Start(t *testing.T) {
	t.Logf("Start command(%s)", c.Name)
	err := c.start()
	require.NoError(t, err, "failed to start command(%s)", c.Name)
}

// Stop stops a Command previously started with Start().
// To do so, it Kill() the process corresponding to this cmd and then wait for
// its termination.
// cmd output is then checked with regard to ExpectedString and ExpectedRegexp
func (c *Command) Stop(t *testing.T) {
	t.Logf("Stop command(%s)\n", c.Name)
	err := c.stop()
	t.Logf("Command returned(%s):\n%s\n%s\n",
		c.Name, c.stderr.String(), c.stdout.String())
	require.NoError(t, err, "failed to kill command(%s)", c.Name)

	c.verifyOutput(t)
}
