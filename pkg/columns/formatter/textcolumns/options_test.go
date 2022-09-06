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

package textcolumns

import "testing"

func TestOptions(t *testing.T) {
	opts := &Options{
		AutoScale:      false,
		ColumnDivider:  "",
		DefaultColumns: nil,
		HeaderStyle:    0,
		RowDivider:     DividerNone,
	}

	WithAutoScale(true)(opts)
	if !opts.AutoScale {
		t.Errorf("expected AutoScale to be true")
	}

	WithColumnDivider("X")(opts)
	if opts.ColumnDivider != "X" {
		t.Errorf("expected ColumnDivider to be X")
	}

	WithDefaultColumns([]string{"abc"})(opts)
	if len(opts.DefaultColumns) != 1 || opts.DefaultColumns[0] != "abc" {
		t.Errorf("expected DefaultColumns to have exactly 'abc' as value")
	}

	WithHeaderStyle(HeaderStyleLowercase)(opts)
	if opts.HeaderStyle != HeaderStyleLowercase {
		t.Errorf("expected HeaderStyle to be HeaderStyleLowercase")
	}

	WithRowDivider("X")(opts)
	if opts.RowDivider != "X" {
		t.Errorf("expected RowDivider to be X")
	}
}
