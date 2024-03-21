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
	"bytes"
	"fmt"
	"os/exec"
	"testing"

	"github.com/blang/semver"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
)

type IG struct {
	command.Command
	path    string
	image   string
	version semver.Version

	env   []string
	flags []string
}

func (ig *IG) createCmd() {
	args := append([]string{"run", ig.image}, ig.flags...)
	cmd := exec.Command(ig.path, args...)

	ig.env = append(ig.env, "IG_EXPERIMENTAL=true")
	cmd.Env = append(cmd.Env, ig.env...)

	ig.Cmd = cmd
}

type option func(*IG)

func WithPath(path string) option {
	return func(ig *IG) {
		ig.path = path
	}
}

func WithImage(image string) option {
	return func(ig *IG) {
		ig.image = image
	}
}

// WithFlags should be in form: "--flag_name=value" or "-shorthand=value"
func WithFlags(flags ...string) option {
	return func(ig *IG) {
		ig.flags = flags
	}
}

// WithEnv vars should be in form: "ENV_VARIABLE_NAME=value"
func WithEnv(env ...string) option {
	return func(ig *IG) {
		ig.env = env
	}
}

func WithStartAndStop() option {
	return func(ig *IG) {
		ig.StartAndStop = true
	}
}

func WithValidateOutput(validateOutput func(t *testing.T, output string)) option {
	return func(ig *IG) {
		ig.ValidateOutput = validateOutput
	}
}

// Runs "ig version" to get the version string
func getIgVersionString(path string) string {
	cmd := exec.Command(path, "version")

	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		fmt.Printf("getting version from ig: %v", err)
		return ""
	}
	return out.String()
}

func extractIgVersion(str string) semver.Version {
	parsedVersion, err := semver.ParseTolerant(str)
	if err != nil {
		fmt.Printf("parsing version from string[%s]: %v]", str, err)
	}
	return parsedVersion
}

// New creates a new IG configured with the options passed as parameters.
// Supported parameters are:
//
//	WithImage(gadget_image)
//	WithPath(string)
//	WithEnv(...string)
//	WithFlags(...string)
//	WithStartAndStop()
func New(opts ...option) *IG {
	ig := &IG{
		path: "ig",
	}

	for _, opt := range opts {
		opt(ig)
	}

	ig.createCmd()

	vstring := getIgVersionString(ig.path)
	ig.version = extractIgVersion(vstring)

	return ig
}
