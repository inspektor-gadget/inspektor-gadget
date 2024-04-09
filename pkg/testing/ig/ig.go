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
	"os"
	"os/exec"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
)

// IGTestConfiguration is responsible for storing configuration of ig executable and provide methods to interact with.
type IGTestConfiguration struct {
	path  string
	image string

	// command.Command contains *exec.Cmd and additional properties and methods for the same.
	command.Command
	flags []string
}

func (ig *IGTestConfiguration) createCmd() {
	ig.flags = append(ig.flags, "-o=json")
	args := append([]string{"run", ig.image}, ig.flags...)
	cmd := exec.Command(ig.path, args...)

	ig.Cmd = cmd
}

type option func(*IGTestConfiguration)

// WithPath used for providing custom path to ig executable.
func WithPath(path string) option {
	return func(ig *IGTestConfiguration) {
		ig.path = path
	}
}

// WithPathFromEnvVar used for reading custom path for ig executable from IG env var.
func WithPathFromEnvVar() option {
	return func(ig *IGTestConfiguration) {
		ig.path = os.Getenv("IG")
	}
}

// WithFlags args should be in form: "--flag_name=value" or "-shorthand=value".
func WithFlags(flags ...string) option {
	return func(ig *IGTestConfiguration) {
		ig.flags = flags
	}
}

// WithStartAndStop used to set StartAndStop value to true.
func WithStartAndStop() option {
	return func(ig *IGTestConfiguration) {
		ig.StartAndStop = true
	}
}

// WithValidateOutput used to compare the actual output with expected output.
func WithValidateOutput(validateOutput func(t *testing.T, output string)) option {
	return func(ig *IGTestConfiguration) {
		ig.ValidateOutput = validateOutput
	}
}

// New creates a new IG configured with the options passed as parameters.
func New(image string, opts ...option) *IGTestConfiguration {
	ig := &IGTestConfiguration{
		path:  "ig",
		image: fmt.Sprintf("%s/%s:%s", os.Getenv("GADGET_REPOSITORY"), image, os.Getenv("GADGET_TAG")),
		Command: command.Command{
			Name: "Run_" + image,
		},
	}

	for _, opt := range opts {
		opt(ig)
	}

	ig.createCmd()

	return ig
}
