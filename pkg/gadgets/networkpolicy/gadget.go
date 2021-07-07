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

package networkpolicy

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
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
	if trace.ObjectMeta.Namespace != "gadget" || trace.ObjectMeta.Name != "network-policy-advisor" {
		opErr := "This gadget only accept operations on the trace named gadget/network-policy-advisor"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	switch operation {
	case "start":
		return g.Start(trace)
	case "update":
		return g.UpdateOutput()
	case "report":
		return g.Report(trace)
	case "stop":
		return g.Stop()
	}
	opErr := fmt.Sprintf("Unknown operation %q", operation)
	return gadgets.StatusUpdate{
		OperationError: &opErr,
	}
}

func (g *Gadget) Start(trace *gadgetv1alpha1.Trace) gadgets.StatusUpdate {
	if g.started {
		opErr := "Already started"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel

	namespaces := ""
	if trace.Spec.Filter != nil {
		namespaces = trace.Spec.Filter.Namespace
	}
	args := []string{
		"-c",
		fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --nomanager --probecleanup --gadget /bin/networkpolicyadvisor -- --namespace %s", namespaces),
	}
	log.Infof("Running /bin/sh %s", strings.Join(args, " "))
	g.cmd = exec.CommandContext(ctx, "/bin/sh", args...)
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
	stateStr := "Started"
	return gadgets.StatusUpdate{
		OperationError: &empty,
		Output:         &empty,
		State:          &stateStr,
	}
}

func (g *Gadget) UpdateOutput() gadgets.StatusUpdate {
	if !g.started {
		opErr := "Not started"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	output := g.out.String()
	log.Infof("Network Policy Advisor output:\n%s\n", output)

	empty := ""
	return gadgets.StatusUpdate{
		OperationError: &empty,
		Output:         &output,
	}
}

func (g *Gadget) Report(trace *gadgetv1alpha1.Trace) gadgets.StatusUpdate {
	advisor := NewAdvisor()
	err := advisor.LoadBuffer([]byte(trace.Status.Output))
	if err != nil {
		opErr := fmt.Sprintf("Cannot parse report: %s", err)
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}

	advisor.GeneratePolicies()
	output := advisor.FormatPolicies()
	empty := ""
	return gadgets.StatusUpdate{
		Output:         &output,
		OperationError: &empty,
	}
}

func (g *Gadget) Stop() gadgets.StatusUpdate {
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
	g.cancel()
	g.cmd.Wait()
	g.started = false
	g.sigtermSent = false

	output := g.out.String()
	log.Infof("Network Policy Advisor output:\n%s\n", output)

	empty := ""
	return gadgets.StatusUpdate{
		OperationError: &empty,
		Output:         &output,
	}
}
