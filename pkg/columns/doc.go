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
Package columns is a library that helps to carry data structs in a more generic way using a combination of reflection and
generics. It can work with any type of struct (and arrays of those), providing useful functions like sorting, grouping,
filtering and printing. How columns are handled can be configured using tags along the struct definition. This keeps
metadata and type data in the same place, avoiding extra and/or duplicated code and thereby the likelihood of typos/errors.

Columns just has to be initialized by passing a prototype of the struct. Afterwards you can use all helper functions
(sorting, grouping, etc.) on it.

# How does it work?

You simply add a "column" tag to members of the struct you want to handle, like so:

	type Event struct {
		Node  string `json:"node" column:"node,width:12,ellipsis:middle"`
		PID   int    `json:"pid" column:"PID,hide,align:right,width:6"`
		Comm  string `json:"comm" column:"Comm"`
		Name  string `json:"name" column:"Name"`
		Dummy string `json:"dummy"`
		Time  int64  `json:"time" column:"Time,align:right,width:24,group:sum"`
	}

Let's briefly analyze:

  - All fields that have a column tag will be considered, that means the `Dummy` field will not be considered.
  - Each column tag starts with the name of the field. This name is case-insensitive (and an error will be thrown if
    multiple fields share the same name.)
  - Additional information on the fields are added as a comma separated list after the name of the column; key and value
    (if applicable) are separated by a colon (see `attributes` below)

You initialize `Columns` by passing it the type of the struct you want to use, like so:

	cols, err := columns.NewColumns[Event]()

The parameter could be used for specific options, passing nil will use the defaults.

# Attributes

	| Attribute | Value(s)               | Description                                                                                                          |
	|-----------|------------------------|----------------------------------------------------------------------------------------------------------------------|
	| align     | left,right             | defines the alignment of the column (whitespace before or after the value)                                           |
	| ellipsis  | none,left,right,middle | defines how situations of content exceeding the given space should be handled, eg: where to place the ellipsis ("…") |
	| fixed     | none                   | defines that this column will have a fixed width, even when auto-scaling is enabled                                  |
	| group     | sum                    | defines what should happen with the field whenever entries are grouped (see grouping)                                |
	| hide      | none                   | specifies that this column is not to be considered by default (see custom columns)                                   |
	| precision | int                    | specifies the precision of floats (number of decimals)                                                               |
	| width     | int                    | defines the space allocated for the column                                                                           |

# Virtual Columns or Custom Extractors

Sometimes it's necessary to add columns on the fly or have special treatment when extracting values. This can be
achieved by specifying a virtual column or custom extractors.

Say that for example you have a struct with a (by default) not printable member `Foo` that you still want to output.

	type Event struct {
		Node  string `json:"node" column:"node,width:12,ellipsis:middle"`
		Foo   []byte
	}

You can do that by adding a virtual column:

	cols.AddColumn(columns.Attributes{
		Name:  "foo",
		Width: 14,
	}, func(e *Event) any {
		return string(e.Foo)
	})

This will convert the []byte to a string before printing it.

You can also just override the default extractor like so:

	cols.SetExtractor("node", func(a *Event) any {
		return "Foobar"
	})
*/
package columns
