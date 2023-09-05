// Copyright 2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/script/types"
)

type Config struct {
	Program string
}

type Tracer struct {
	eventCallback func(ev *types.Event)
	config        Config
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	flavour := os.Getenv("GADGET_IMAGE_FLAVOUR")
	if flavour != "bcc" {
		return fmt.Errorf("script is not supported on the %q flavour of the container image. Only \"bcc\" is supported for now",
			flavour)
	}

	params := gadgetCtx.GadgetParams()
	t.config.Program = params.Get(ParamProgram).AsString()
	log := gadgetCtx.Logger()

	// TODO: Consider using CommandContext() once we support Go 1.20
	cmd := exec.Command("bpftrace", "-e", t.config.Program)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("getting stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("getting stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("running bpftrace: %w", err)
	}

	// read and send stdout as events
	go func() {
		scanner := bufio.NewScanner(stdout)

		for scanner.Scan() {
			t.eventCallback(&types.Event{
				Output: scanner.Text(),
			})
		}

		if err := scanner.Err(); err != nil {
			log.Error("error reading bpftrace output: %s", err)
		}
	}()

	// print stderr through logger
	go func() {
		scanner := bufio.NewScanner(stderr)

		for scanner.Scan() {
			log.Error(scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.Error("error reading bpftrace output: %s", err)
		}
	}()

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		log.Errorf("failed to stop process: %s", err)
		return nil
	}

	if err := cmd.Wait(); err != nil {
		log.Errorf("failed to wait process: %s", err)
		return nil
	}

	return nil
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}
