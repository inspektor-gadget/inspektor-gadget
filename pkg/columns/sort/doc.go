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

/*
Package sort can be used to sort an array by their columns in either ascending or descending order.

Calling

	sort.SortEntries(columnMap, entries, []string{"node", "-time"})

for example sorts the array by the time column in descending order and afterwards by the node column.

The "-" prefix means the sorter should use descending order. Sorting by multiple fields will be done from the last field
to the first in a stable way - so the first column always gets the highest priority.
*/
package sort
