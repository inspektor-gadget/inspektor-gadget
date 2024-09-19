// Copyright 2024 The Inspektor Gadget authors
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

package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

func TestDaemonHeadless(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.Runtime == containers.RuntimeKubernetes {
		t.Skip("Skipping for k8s")
		return
	}

	image := "trace_exec"
	repository := os.Getenv("GADGET_REPOSITORY")
	tag := os.Getenv("GADGET_TAG")
	if repository != "" {
		image = fmt.Sprintf("%s/%s", repository, image)
	}
	if tag != "" {
		image = fmt.Sprintf("%s:%s", image, tag)
	}

	igCmd := "ig"
	gadgetctlCmd := "gadgetctl"

	if path, ok := os.LookupEnv("IG_PATH"); ok {
		// assume gadgetctl next to ig binary
		igCmd = path
		if path != "ig" {
			gadgetctlCmd = filepath.Join(filepath.Dir(path), "gadgetctl")
		}
	}

	igtesting.RunTestSteps([]igtesting.TestStep{
		&command.Command{
			Name:           "Start Daemon",
			ValidateOutput: nil,
			StartAndStop:   true,
			Cmd:            exec.Command(igCmd, "daemon"),
		},
		utils.Sleep(time.Second * 5),
		&command.Command{
			Name: "Launch Gadget",
			Cmd:  exec.Command(gadgetctlCmd, "run", image, "--detach", "--name", "foobar", "--id", "00000000000000000000000000000000"),
		},
		&command.Command{
			Name: "List Gadget",
			Cmd:  exec.Command(gadgetctlCmd, "list"),
			ValidateOutput: func(t *testing.T, output string) {
				require.Contains(t, output, "foobar")
			},
		},
		&command.Command{
			Name: "Delete Gadget",
			Cmd:  exec.Command(gadgetctlCmd, "d", "foobar"),
			ValidateOutput: func(t *testing.T, output string) {
				require.Contains(t, output, "00000000000000000000000000000000")
			},
		},
		&command.Command{
			Name: "List Gadget",
			Cmd:  exec.Command(gadgetctlCmd, "list"),
			ValidateOutput: func(t *testing.T, output string) {
				require.NotContains(t, output, "foobar")
			},
		},
	}, t)
}
