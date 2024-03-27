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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/blang/semver"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
)

// IGTestConfiguration is responsible for storing configuration of ig executable and provide methods to interact with.
type IGTestConfiguration struct {
	path    string
	image   string
	version semver.Version

	// command.Command contains *exec.Cmd and additional properties and methods for the same.
	command.Command
	flags []string
}

func (ig *IGTestConfiguration) createCmd() {
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

// WithImage used to provide image-based gadget's name without gadget repository and tag.
func WithImage(image string) option {
	return func(ig *IGTestConfiguration) {
		ig.image = image
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

func WithCommandName(name string) option {
	return func(ig *IGTestConfiguration) {
		ig.Name = name
	}
}

// Runs "ig version" to get the version string
func getIgVersionString(path string) string {
	cmd := exec.Command(path, "version")

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		fmt.Printf("getting version from ig: %v\n", err)
		return ""
	}
	return out.String()
}

func extractIgVersion(str string) semver.Version {
	parsedVersion, err := semver.ParseTolerant(str)
	if err != nil {
		fmt.Printf("parsing version from string[%s]: %v\n]", str, err)
	}
	return parsedVersion
}

// New creates a new IG configured with the options passed as parameters.
// Supported parameters are:
//
//	WithImage(gadget_image)
//	WithPath(string)
//	WithFlags(...string)
//	WithStartAndStop()
//	WithValidateOutput(validateOutput func(t *testing.T, output string))
//	WithCommandName(name string)
func New(opts ...option) *IGTestConfiguration {
	ig := &IGTestConfiguration{
		path: "ig",
	}

	for _, opt := range opts {
		opt(ig)
	}

	if ig.Name == "" {
		ig.Name = "Run_" + ig.image
	}

	ig.createCmd()

	vstring := getIgVersionString(ig.path)
	ig.version = extractIgVersion(vstring)

	return ig
}
