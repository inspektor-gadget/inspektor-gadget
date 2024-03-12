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
	"os"
	"os/exec"

	"github.com/blang/semver"
)

type IG struct {
	path    string
	image   string
	version semver.Version
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

// Runs "ig version" to get the version string
func getIgVersionString(path string) (string, error) {
	cmd := exec.Command(path, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// Returns the first three components of the version
// e.g. "v0.26.0" would return (0, 26, 0)
func extractIgVersion(str string) (semver.Version, error) {
	parsedVersion, err := semver.ParseTolerant(str)
	if err != nil {
		return parsedVersion, fmt.Errorf("parsing version from string[%s]: %w]", str, err)
	}
	return parsedVersion, nil
}

// New creates a new IG configured with the options passed as parameters.
// Supported parameters are:
//
//	WithImage(gadget_image)
//	WithPath(string)
func New(opts ...option) (*IG, error) {

	ig := &IG{
		path: "ig",
	}

	for _, opt := range opts {
		opt(ig)
	}

	vstring, err := getIgVersionString(ig.path)
	if err != nil {
		return nil, fmt.Errorf("obtaining ig version: %w", err)
	}
	parsedVersion, err := extractIgVersion(vstring)
	if err != nil {
		return nil, fmt.Errorf("extracting ig version: %w", err)
	}
	ig.version = parsedVersion

	return ig, nil
}

func (ig *IG) Pull(flags ...string) error {
	cmd := append([]string{"image", "pull", ig.image}, flags...)
	if err := ig.runWithOutput(cmd); err != nil {
		return err
	}
	return nil
}

func (ig *IG) Push(flags ...string) error {
	cmd := append([]string{"image", "push", ig.image}, flags...)
	if err := ig.runWithOutput(cmd); err != nil {
		return err
	}
	return nil
}

func (ig *IG) Remove(flags ...string) error {
	cmd := append([]string{"image", "remove", ig.image}, flags...)
	if err := ig.runWithOutput(cmd); err != nil {
		return err
	}
	return nil
}

func (ig *IG) Run(flags ...string) error {
	cmd := append([]string{"run", ig.image}, flags...)
	if err := ig.runWithOutput(cmd); err != nil {
		return err
	}
	return nil
}

// runWithOutput runs an ig command with the given arguments,
// writing any stdout output to the os output
// TODO: replace os with custom
func (ig *IG) runWithOutput(args []string) error {
	cmd := exec.Command(ig.path, args...)
	cmd.Env = append(cmd.Env, "IG_EXPERIMENTAL=true")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		switch e := err.(type) {
		case *exec.Error:
			return fmt.Errorf("command execution: %w", err)
		case *exec.ExitError:
			return fmt.Errorf("command exit code = %d", e.ExitCode())
		default:
			return err
		}
	}

	return nil
}
