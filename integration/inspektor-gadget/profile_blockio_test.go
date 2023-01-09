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

package main

import (
	"testing"

	bioprofileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestProfileBlockIO(t *testing.T) {
	t.Parallel()

	commands := []*Command{
		{
			Name: "RunProfileBlockIOGadget",
			Cmd:  "$KUBECTL_GADGET profile block-io --node $(kubectl get node --no-headers | cut -d' ' -f1 | head -1) --timeout 15 -o json",
			ExpectedOutputFn: func(output string) error {
				expectedEntry := &bioprofileTypes.Report{
					ValType: "usecs",
				}

				normalize := func(e *bioprofileTypes.Report) {
					e.Data = nil
					e.Time = ""
				}

				return ExpectEntriesToMatch(output, normalize, expectedEntry)
			},
		},
	}

	RunTestSteps(commands, t)
}
