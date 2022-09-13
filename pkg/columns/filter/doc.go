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
Package filter helps filtering an array of structs that were analyzed by the columns library.

If you have an array of a struct you have a `Column` instance for, you can simply filter it by using a filter string
like this:

	filter.FilterEntries(columnMap, events, []string{"pid:55"})

This will return an array only containing entries that have the pid column set to 55.

A filter string always starts with the column name, followed by a colon and then the actual filter rule.

If the filter rule starts with an exclamation mark ("!"), the filter will be negated and return only entries that don't
match the rule. This indicator has always be the first character of the filter rule.

	filter.FilterEntries(columnMap, events, "name:!Demo") // matches entries with column "name" not being "Demo"

A tilde ("~") at the start of a filter rule indicates a regular expression. The actual regular expression has to be
written using the re2 syntax used by Go (see [https://github.com/google/re2/wiki/Syntax]).

Additional rule options for integers, floats and strings are `>`, `>=`, `<` and `<=`, e.g.:

	filter.FilterEntries(columnMap, events, []string{"pid:>=55"})

# Optimizing / Streaming

If you have to filter a stream of incoming events, you can use

	myFilter := filter.GetFilterFromString(columnMap, filter)

to get a filter with a .Match(entry) function that you can use to match against entries.

# Filter examples

	"columnName:value" - matches, if the content of columnName equals exactly value
	"columnName:!value" - matches, if the content of columnName does not equal exactly value
	"columnName:>=value" - matches, if the content of columnName is greater or equal to the value
	"columnName:~value" - matches, if the content of columnName matches the regular expression 'value'
*/
package filter
