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

package snapshot

import (
	"strings"

	"github.com/spf13/cobra"
)

var SnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Take a snapshot of a subsystem and print it",
}

// buildSnapshotColsHeader returns a header with the requested custom columns
// that exist in the availableCols. The columns are separated by taps.
func buildSnapshotColsHeader(availableCols map[string]struct{}, requestedCols []string) string {
	var sb strings.Builder

	for _, col := range requestedCols {
		if _, ok := availableCols[col]; ok {
			sb.WriteString(strings.ToUpper(col) + "\t")
		}
	}

	return sb.String()
}
