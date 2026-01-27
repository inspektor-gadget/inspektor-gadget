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

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptions(t *testing.T) {
	opts := &Options{
		AutoScale:      false,
		ColumnDivider:  "",
		DefaultColumns: nil,
		HeaderStyle:    0,
		RowDivider:     DividerNone,
	}

	WithAutoScale(true)(opts)
	require.True(t, opts.AutoScale, "Expected AutoScale to be true")

	WithColumnDivider("X")(opts)
	require.Equal(t, "X", opts.ColumnDivider)

	WithDefaultColumns([]string{"abc"})(opts)
	require.Len(t, opts.DefaultColumns, 1)
	require.Equal(t, "abc", opts.DefaultColumns[0])

	WithHeaderStyle(HeaderStyleLowercase)(opts)
	require.Equal(t, HeaderStyleLowercase, opts.HeaderStyle)

	WithRowDivider("X")(opts)
	require.Equal(t, "X", opts.RowDivider)
}
