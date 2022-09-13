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
Package textcolumns helps to output structs (and events of structs) using metadata from a `Columns` instance in a
tabular way suitable for consoles or other frontends using fixed-width characters / fonts.

It can automatically size the output tables according to either screen size or content and provides some helpful tools
to get a consistent output.

# Initializing

You can create a new formatter by calling

	tc := textcolumns.NewFormatter(columnMap)

You can specify options by adding one or more of the WithX() functions to the initializer.
The [columns.ColumnMap] can be obtained by calling [columns.GetColumpMap] on your `Column` instance.

# Output

After you have initialized the formatter, you can use

	tc.FormatHeader()

to obtain the header line as string, which will look something like this:

	NODE                PID COMM             NAME                                 TIME

You can also pass a filled struct to

	tc.FormatEntry(&event)

to get a string like this:

	Node1                 2 AAA                                                   12ns

Even simpler, use

	tc.WriteTable(os.Stdout, entries)

to directly print the whole table:

	NODE                PID COMM             NAME                                 TIME
	----------------------------------------------------------------------------------
	Node1                 2 AAA                                                   12ns
	Node1                 1 AAA              Yay                           14.677772ms
	Node1                 2 AnotherComm                                    24.645772ms
	Node2                 4 BBB                                           3.462217772s
	Node2                 3 BBB                                                  333ns

# Custom Columns

By default, Columns will show all fields that have a column tag without the `hide` attribute. Using

	tc.SetShowColumns("node,time")

you can adjust the output to contain exactly the specified columns.
*/
package textcolumns
