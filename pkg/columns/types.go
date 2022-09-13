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

// Alignment defines whether text should be aligned to the left or right inside a column
type Alignment int

const (
	AlignLeft Alignment = iota
	AlignRight
)

// GroupType defines how columns should be aggregated in case of grouping
type GroupType int

const (
	GroupTypeNone GroupType = iota // GroupTypeNone uses the first occurrence of a value in a group to represent its group
	GroupTypeSum                   // GroupTypeSum adds values of this column up for its group
)

// Order defines the sorting order of columns
type Order bool

const (
	OrderAsc  Order = true  // OrderAsc sorts in ascending alphanumerical order
	OrderDesc Order = false // OrderDesc sorts in descending alphanumerical order
)

type ColumnMatcher interface {
	HasTag(string) bool
	HasNoTags() bool
	IsEmbedded() bool
}

// ColumnInterface is an interface that is valid for Columns and ColumnMap
type ColumnInterface[T any] interface {
	GetColumn(columnName string) (*Column[T], bool)
	GetColumnMap(filters ...ColumnFilter) ColumnMap[T]
	GetOrderedColumns(filters ...ColumnFilter) []*Column[T]
	GetColumnNames(filters ...ColumnFilter) []string
}
