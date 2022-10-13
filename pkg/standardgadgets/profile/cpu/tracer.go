// Copyright 2019-2022 The Inspektor Gadget authors
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

package standard

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/tracer"
)

type Tracer struct {
	cmd               *exec.Cmd
	stdout            *bytes.Buffer
	stderr            *bytes.Buffer
	mountnsMapPinPath string
}

func NewTracer(config *tracer.Config) (*Tracer, error) {
	mountNsMapPinPath := filepath.Join(gadgets.PinPath, uuid.New().String())
	if err := config.MountnsMap.Pin(mountNsMapPinPath); err != nil {
		return nil, fmt.Errorf("failed to pin tracer's mount ns map: %w", err)
	}

	cmd := exec.Command("/usr/share/bcc/tools/profile", "--json",
		"--containersmap", "/sys/fs/bpf/gadget/containers",
		"--mntnsmap", mountNsMapPinPath)

	if config.UserStackOnly {
		cmd.Args = append(cmd.Args, "-U")
	}

	if config.KernelStackOnly {
		cmd.Args = append(cmd.Args, "-K")
	}

	stdout := bytes.NewBuffer([]byte{})
	stderr := bytes.NewBuffer([]byte{})

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	return &Tracer{
		cmd:               cmd,
		stdout:            stdout,
		stderr:            stderr,
		mountnsMapPinPath: mountNsMapPinPath,
	}, nil
}

func (t *Tracer) Stop() (string, error) {
	err := t.cmd.Process.Signal(syscall.SIGINT)
	if err != nil {
		return "", fmt.Errorf(
			"failed to send SIGINT to process: %w (stdout: %q stderr: %q)",
			err,
			t.stdout.String(),
			t.stderr.String(),
		)
	}

	err = t.cmd.Wait()
	if err != nil {
		return "", fmt.Errorf(
			"failed to wait for process: %w (stdout: %q stderr: %q)",
			err,
			t.stdout.String(),
			t.stderr.String(),
		)
	}

	os.Remove(t.mountnsMapPinPath)

	return strings.ReplaceAll(t.stdout.String(), "'", `"`), nil
}
