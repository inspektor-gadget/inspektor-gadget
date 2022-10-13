// Copyright 2022 The Inspektor Gadget authors
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

package columns

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/ellipsis"
)

func TestOptions(t *testing.T) {
	opts := GetDefault()

	WithAlignment(AlignRight)(opts)
	if opts.DefaultAlignment != AlignRight {
		t.Errorf("Expected default alignment to be AlignRight")
	}

	WithEllipsis(ellipsis.Middle)(opts)
	if opts.DefaultEllipsis != ellipsis.Middle {
		t.Errorf("Expected ellipsis to be ellipsis.Middle")
	}

	WithWidth(2342)(opts)
	if opts.DefaultWidth != 2342 {
		t.Errorf("Expected default width to be 2342")
	}
}
