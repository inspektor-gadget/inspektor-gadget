// Copyright 2026 The Inspektor Gadget authors
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

package image

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

type commandRunner interface {
	run(cmd []string, env []string) (stdout string, stderr string, err error)
}

type localRunner struct {
	verbose bool
}

func (r *localRunner) run(cmd []string, env []string) (string, string, error) {
	if r.verbose {
		fmt.Printf("%s\n", strings.Join(cmd, " "))
	}
	command := exec.Command(cmd[0], cmd[1:]...)
	if len(env) > 0 {
		command.Env = append(os.Environ(), env...)
	}
	out, err := command.CombinedOutput()
	if r.verbose && len(out) > 0 {
		fmt.Printf("%s", out)
	}
	if err != nil {
		return string(out), "", fmt.Errorf("running %v: %w: %s", cmd, err, out)
	}
	return string(out), "", nil
}

type containerRunner struct {
	ctx         context.Context
	cli         *client.Client
	containerID string
	verbose     bool
}

func (r *containerRunner) run(cmd []string, env []string) (string, string, error) {
	if r.verbose {
		fmt.Printf("%s\n", strings.Join(cmd, " "))
	}
	outBuf, errBuf, exitCode, err := execCmdInContainer(r.ctx, r.cli, r.containerID, cmd, env)
	if r.verbose && len(outBuf) > 0 {
		fmt.Printf("%s", outBuf)
	}
	if r.verbose && len(errBuf) > 0 {
		fmt.Printf("%s", errBuf)
	}
	if err != nil {
		return outBuf, errBuf, err
	}
	if exitCode != 0 {
		return outBuf, errBuf, fmt.Errorf("command %v exited with status %d: %s", cmd, exitCode, errBuf)
	}
	return outBuf, errBuf, nil
}

func execCmdInContainer(ctx context.Context, cli *client.Client, containerID string, cmd []string, env []string) (string, string, int, error) {
	execCfg, err := cli.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		Cmd:          cmd,
		Env:          env,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", "", -1, fmt.Errorf("creating container exec: %w", err)
	}

	attach, err := cli.ExecAttach(ctx, execCfg.ID, client.ExecAttachOptions{})
	if err != nil {
		return "", "", -1, fmt.Errorf("attaching exec to container: %w", err)
	}
	defer attach.Close()

	var outBuf, errBuf bytes.Buffer
	_, err = stdcopy.StdCopy(&outBuf, &errBuf, attach.Reader)
	if err != nil {
		return "", "", -1, fmt.Errorf("copying exec output: %w", err)
	}

	inspect, err := cli.ExecInspect(ctx, execCfg.ID, client.ExecInspectOptions{})
	if err != nil {
		return outBuf.String(), errBuf.String(), -1, fmt.Errorf("inspecting exec: %w", err)
	}

	return outBuf.String(), errBuf.String(), inspect.ExitCode, nil
}
