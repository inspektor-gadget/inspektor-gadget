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

package filter_test

import (
	"fmt"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/filter"
)

func ExampleFilterEntries() {
	type Employee struct {
		Name       string `column:"name" columnTags:"sensitive"`
		Age        int    `column:"age" columnTags:"sensitive"`
		Department string `column:"department"`
	}

	Employees := []*Employee{
		{"Alice", 32, "Security"},
		{"Bob", 26, "Security"},
		{"Eve", 99, "Security also"},
	}

	employeeColumns := columns.MustCreateColumns[Employee]()

	// Get columnMap
	cmap := employeeColumns.GetColumnMap()

	// Filter entries, searching for people younger than 50 and an "e" in the name (case insensitive)
	result, err := filter.FilterEntries(cmap, Employees, []string{"age:<50", "name:~(?i)e"})
	if err != nil {
		panic(err)
	}

	for _, e := range result {
		fmt.Println(*e)
	}

	// Output:
	// {Alice 32 Security}
}

func ExampleGetFilterFromString() {
	type Employee struct {
		Name       string `column:"name" columnTags:"sensitive"`
		Age        int    `column:"age" columnTags:"sensitive"`
		Department string `column:"department"`
	}

	Employees := []*Employee{
		{"Alice", 32, "Security"},
		{"Bob", 26, "Security"},
		{"Eve", 99, "Security also"},
	}

	employeeColumns := columns.MustCreateColumns[Employee]()

	// Get columnMap
	cmap := employeeColumns.GetColumnMap()

	// Create a new filter that matches employees from the "Security" department
	employeeFilter, err := filter.GetFilterFromString(cmap, "department:Security")
	if err != nil {
		panic(err)
	}

	for _, e := range Employees {
		if employeeFilter.Match(e) {
			fmt.Println(*e)
		}
	}

	// Output:
	// {Alice 32 Security}
	// {Bob 26 Security}
}
