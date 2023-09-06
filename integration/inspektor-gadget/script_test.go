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

package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestScript(t *testing.T) {
	ns := GenerateTestNamespaceName("test-script")

	t.Parallel()

	prog := `kretprobe:inet_bind { printf("fofofofof %s\n", comm); }`

	traceOpenCmd := &Command{
		Name:         "StartScriptGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET script -o json -e '%s'", prog),
		StartAndStop: true,
		ValidateOutput: func(t *testing.T, output string) {
			require.Contains(t, output, "fofofofof nc")
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceOpenCmd,
		BusyboxPodRepeatCommand(ns, "nc -l 127.0.0.1 -p 9090 -w 1"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}
