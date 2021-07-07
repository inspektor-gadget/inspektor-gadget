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

package biolatency

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
)

type Gadget struct {
	started     bool
	sigtermSent bool
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	out         bytes.Buffer
}

func (g *Gadget) Delete(trace types.NamespacedName) error {
	log.Infof("Deleting %s", trace.String())
	if g.started {
		g.cancel()
		g.cmd.Wait()
	}
	return nil
}

func (g *Gadget) Operation(trace *gadgetv1alpha1.Trace, operation string, params map[string]string) gadgets.StatusUpdate {
	if trace.ObjectMeta.Namespace != "gadget" {
		opErr := "This gadget only accept operations on traces in the gadget namespace"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	switch operation {
	case "start":
		return g.Start()
	case "update":
		return g.UpdateOutput()
	case "stop":
		return g.Stop()
	}
	opErr := fmt.Sprintf("Unknown operation %q", operation)
	return gadgets.StatusUpdate{
		OperationError: &opErr,
	}
}

func (g *Gadget) Start() gadgets.StatusUpdate {
	if g.started {
		opErr := "Already started"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.cmd = exec.CommandContext(ctx, "/usr/share/bcc/tools/biolatency")
	g.cmd.Stdout = &g.out
	err := g.cmd.Start()
	if err != nil {
		opErr := fmt.Sprintf("Failed to start: %s", err)
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	g.started = true

	empty := ""
	stateStarted := "Started"
	return gadgets.StatusUpdate{
		OperationError: &empty,
		Output:         &empty,
		State:          &stateStarted,
	}
}

func (g *Gadget) UpdateOutput() gadgets.StatusUpdate {
	if !g.started {
		opErr := "Not started"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	if !g.sigtermSent {
		g.cmd.Process.Signal(syscall.SIGINT)
		g.sigtermSent = true
	}
	output := g.out.String()
	fmt.Printf("Output:\n%s\n", output)

	empty := ""
	return gadgets.StatusUpdate{
		OperationError: &empty,
		Output:         &output,
	}
}

func (g *Gadget) Stop() gadgets.StatusUpdate {
	if !g.started {
		opErr := "Not started"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	g.cancel()
	g.cmd.Wait()
	g.started = false
	g.sigtermSent = false

	output := g.out.String()
	fmt.Printf("Output:\n%s\n", output)

	empty := ""
	return gadgets.StatusUpdate{
		OperationError: &empty,
		Output:         &output,
	}
}
