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

// Package ig provides executable wrapper for ig binary.
//
// Mainly used for testing of image-based gadgets.
package ig

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

// runner is responsible for storing configuration of ig executable and provide methods to interact with.
type runner struct {
	path       string
	image      string
	outputMode string

	// command.Command contains *exec.Cmd and additional properties and methods for the same.
	command.Command
	flags []string
}

func (ig *runner) createCmd() {
	ig.flags = append(ig.flags, "-o="+ig.outputMode)
	args := append([]string{"run", ig.image}, ig.flags...)

	ig.Cmd = exec.Command(ig.path, args...)
}

type Option func(*runner)

// WithPath used for providing custom path to ig executable.
func WithPath(path string) Option {
	return func(ig *runner) {
		ig.path = path
	}
}

// WithFlags args should be in form: "--flag_name=value" or "-shorthand=value".
func WithFlags(flags ...string) Option {
	return func(ig *runner) {
		ig.flags = append(ig.flags, flags...)
	}
}

// WithStartAndStop used to set StartAndStop value to true.
func WithStartAndStop() Option {
	return func(ig *runner) {
		ig.StartAndStop = true
	}
}

// WithValidateOutput used to compare the actual output with expected output.
func WithValidateOutput(validateOutput func(t *testing.T, output string)) Option {
	return func(ig *runner) {
		ig.ValidateOutput = validateOutput
	}
}

// WithValidateStderrOutput used to compare the actual output with expected output.
func WithValidateStderrOutput(validateOutput func(t *testing.T, output string)) Option {
	return func(ig *runner) {
		ig.ValidateStdErrOutput = validateOutput
	}
}

// WithStdOutWriter sets a writes that receives the standard output of the command.
func WithStdOutWriter(writer io.Writer) Option {
	return func(ig *runner) {
		ig.StdOutWriter = writer
	}
}

// WithOutputMode sets the output mode
func WithOutputMode(outputMode string) Option {
	return func(ig *runner) {
		ig.outputMode = outputMode
	}
}

// New creates a new IG configured with the Options passed as parameters.
func New(image string, opts ...Option) igtesting.TestStep {
	commandName := fmt.Sprintf("Run_%s", image)
	image = gadgetrunner.GetGadgetImageName(image)

	factoryRunner := &runner{
		path:       "ig",
		image:      image,
		outputMode: "json",
		Command: command.Command{
			Name: commandName,
		},
	}

	if path, ok := os.LookupEnv("IG_PATH"); ok {
		factoryRunner.path = path
	}

	// append IG_FLAGS flags separately to ensure
	// one from the option aren't overwritten
	if flags, ok := os.LookupEnv("IG_FLAGS"); ok {
		split := strings.Split(flags, " ")
		factoryRunner.flags = append(factoryRunner.flags, split...)
	}

	for _, opt := range opts {
		opt(factoryRunner)
	}

	factoryRunner.createCmd()

	return factoryRunner
}
