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

package collectorprocess

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

type Gadget struct {
}

func (g *Gadget) Delete(trace types.NamespacedName) error {
	log.Infof("Deleting %s", trace.String())
	return nil
}

func (g *Gadget) Operation(trace *gadgetv1alpha1.Trace, operation string, params map[string]string) gadgets.StatusUpdate {
	if trace.ObjectMeta.Namespace != "gadget" {
		opErr := "This gadget only accept operations on traces in the gadget namespace"
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}
	if operation != "run" {
		opErr := fmt.Sprintf("Unknown operation: %q", operation)
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}

	args := []string{}
	if trace.Spec.Filter != nil {
		args = []string{"-mntnsmap", gadgets.TracePinPathFromNamespacedName(types.NamespacedName{
			Name:      trace.GetName(),
			Namespace: trace.GetNamespace(),
		})}
	}

	log.Infof("Running collector-process %s", strings.Join(args, " "))
	cmd := exec.Command("collector-process", args...)
	stdoutStderr, err := cmd.CombinedOutput()
	stdoutStderrStr := string(stdoutStderr)
	if err != nil {
		log.Infof("collector-process failed: %s\n%s", err, stdoutStderrStr)
		opErr := fmt.Sprintf("Failed to exec collector-process: %s: %s", err.Error(), stdoutStderrStr)
		return gadgets.StatusUpdate{
			OperationError: &opErr,
		}
	}

	log.Infof("collector-process returned: %d characters", len(stdoutStderrStr))

	msgReady := "Ready"
	empty := ""
	return gadgets.StatusUpdate{
		Output:         &stdoutStderrStr,
		State:          &msgReady,
		OperationError: &empty,
	}
}
