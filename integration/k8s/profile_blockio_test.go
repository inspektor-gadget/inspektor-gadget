// Copyright 2022-2023 The Inspektor Gadget authors
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

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	bioprofileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestProfileBlockIO(t *testing.T) {
	t.Parallel()

	var extraArgs string
	if DefaultTestComponent == InspektorGadgetTestComponent {
		extraArgs = "--node $(kubectl get node --no-headers | cut -d' ' -f1 | head -1)"
	}

	profileBioCmd := &Command{
		Name: "ProfileBlockIO",
		Cmd:  fmt.Sprintf("%s profile block-io -o json --timeout 15 %s", DefaultTestComponent, extraArgs),
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := bioprofileTypes.NewReport(histogram.UnitMicroseconds, nil)

			normalize := func(e *bioprofileTypes.Report) {
				e.Intervals = nil
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}

	RunTestSteps([]TestStep{profileBioCmd}, t, WithCbBeforeCleanup(PrintLogsFn()))
}
