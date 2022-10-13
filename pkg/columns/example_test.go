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

package columns_test

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/filter"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
)

type Employee struct {
	Name       string `column:"name" columnTags:"sensitive"`
	Age        int    `column:"age" columnTags:"sensitive"`
	Department string `column:"department"`
}

var Employees = []*Employee{
	{"Alice", 32, "Security"},
	{"Bob", 26, "Security"},
	{"Eve", 99, "Security also"},
}

// Defining the column helper here lets the program crash on start if there are
// errors in the syntax
var employeeColumns = columns.MustCreateColumns[Employee]()

func Example() {
	out := bytes.NewBuffer(nil)

	// Get columnMap
	cmap := employeeColumns.GetColumnMap()

	// Get a new formatter
	formatter := textcolumns.NewFormatter(cmap, textcolumns.WithRowDivider(textcolumns.DividerDash))

	// Output the whole table
	formatter.WriteTable(out, Employees)

	out.WriteString("\n")

	// Reverse the order by name and output again
	sort.SortEntries[Employee](cmap, Employees, []string{"-name"})
	formatter.WriteTable(out, Employees)

	out.WriteString("\n")

	// Now only get security personell
	securityOnly, err := filter.FilterEntries[Employee](cmap, Employees, []string{"department:Security"})
	if err != nil {
		panic(err)
	}
	formatter.WriteTable(out, securityOnly)

	out.WriteString("\n")

	// Confidentiality!
	formatter = textcolumns.NewFormatter(employeeColumns.GetColumnMap(columns.WithoutTag("sensitive")), textcolumns.WithRowDivider(textcolumns.DividerDash))
	formatter.WriteTable(out, securityOnly)

	// Split output by newline and remove whitespace at the end of each line to match test output below
	outLines := strings.Split(out.String(), "\n")
	for _, line := range outLines {
		fmt.Println(strings.TrimRight(line, " "))
	}

	// Output:
	// NAME             AGE              DEPARTMENT
	// ——————————————————————————————————————————————————
	// Alice            32               Security
	// Bob              26               Security
	// Eve              99               Security also
	//
	// NAME             AGE              DEPARTMENT
	// ——————————————————————————————————————————————————
	// Eve              99               Security also
	// Bob              26               Security
	// Alice            32               Security
	//
	// NAME             AGE              DEPARTMENT
	// ——————————————————————————————————————————————————
	// Bob              26               Security
	// Alice            32               Security
	//
	// DEPARTMENT
	// ————————————————
	// Security
	// Security
}
