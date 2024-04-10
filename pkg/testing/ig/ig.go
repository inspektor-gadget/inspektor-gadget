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
	"os/exec"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
)

type Opts struct {
	Path           string
	Flags          []string
	StartAndStop   bool
	ValidateOutput func(t *testing.T, output string)
}

// IGTestConfiguration is responsible for storing configuration of ig executable and provide methods to interact with.
type IGTestConfiguration struct {
	// command.Command contains *exec.Cmd and additional properties and methods for the same.
	command.Command
	opts  Opts
	image string
}

func (ig *IGTestConfiguration) createCmd() {
	ig.opts.Flags = append(ig.opts.Flags, "-o=json")
	args := append([]string{"run", ig.image}, ig.opts.Flags...)
	cmd := exec.Command(ig.opts.Path, args...)

	ig.StartAndStop = ig.opts.StartAndStop
	ig.ValidateOutput = ig.opts.ValidateOutput

	ig.Cmd = cmd
}

// New creates a new IG configured with the options passed as parameters.
func New(image string, opts Opts) *IGTestConfiguration {
	if opts.Path == "" {
		opts.Path = "ig"
	}

	ig := &IGTestConfiguration{
		Command: command.Command{
			Name: "Run_" + image,
		},
		opts:  opts,
		image: image,
	}

	ig.createCmd()

	return ig
}
