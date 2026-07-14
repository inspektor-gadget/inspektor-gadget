// Copyright 2022-2023 The Inspektor Gadget authors
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
Package parser wraps a couple of helper libraries with the intention of hiding
type information and simplifying data handling outside the gadgets. It can be used to
wire the events of gadgets directly to the column formatter.
*/
package parser

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
)

// Parser is the (untyped) interface used for parser
type Parser interface {
	// GetTextColumnsFormatter returns the default formatter for this columns instance
	GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter

	// GetColumnAttributes returns a map of column names to their respective attributes
	GetColumnAttributes() []columns.Attributes

	// GetDefaultColumns returns a list of columns that are visible by default; optionally, hiddenTags will
	// hide columns that contain any of the given tags
	GetDefaultColumns(hiddenTags ...string) []string

	// GetColumns returns the underlying columns definition (mainly used for serialization)
	GetColumns() any

	// VerifyColumnNames takes a list of column names and returns two lists, one containing the
	// valid column names and another containing the invalid column names. Prefixes like "-" for
	// descending sorting will be ignored.
	VerifyColumnNames(columnNames []string) (valid []string, invalid []string)

	// SetColumnFilters sets additional column filters that will be used whenever one of the other methods of this
	// interface are called. This is for example used to filter columns with information on kubernetes in a non-k8s
	// environment like ig
	SetColumnFilters(...columns.ColumnFilter)

	// EventHandlerFunc returns a function that accepts an instance of type *T and pushes it downstream after applying
	// enrichers
	EventHandlerFunc(enrichers ...func(any) error) any
	EventHandlerFuncArray(enrichers ...func(any) error) any

	// SetEventCallback sets the downstream callback
	SetEventCallback(eventCallback any)
}

type parser[T any] struct {
	columns            *columns.Columns[T]
	eventCallback      func(*T)
	eventCallbackArray func([]*T)
	columnFilters      []columns.ColumnFilter
}

func NewParser[T any](columns *columns.Columns[T]) Parser {
	p := &parser[T]{
		columns: columns,
	}
	return p
}

func (p *parser[T]) SetColumnFilters(filters ...columns.ColumnFilter) {
	p.columnFilters = filters
}

func (p *parser[T]) SetEventCallback(eventCallback any) {
	switch cb := eventCallback.(type) {
	case func(*T):
		// Typed, can be used as eventCallback directly
		p.eventCallback = cb
	case func([]*T):
		// Typed array, can be used as eventCallback directly
		p.eventCallbackArray = cb
	case func(any):
		// Generic callback function (e.g. to print JSON)
		p.eventCallback = func(ev *T) {
			cb(ev)
		}
		p.eventCallbackArray = func(ev []*T) {
			cb(ev)
		}
	default:
		panic("cannot use event callback for parser")
	}
}

func (p *parser[T]) eventHandler(cb func(*T), enrichers ...func(any) error) func(*T) {
	if cb == nil {
		panic("cb can't be nil in eventHandler from parser")
	}
	return func(ev *T) {
		for _, enricher := range enrichers {
			enricher(ev)
		}
		cb(ev)
	}
}

func (p *parser[T]) eventHandlerArray(cb func([]*T), enrichers ...func(any) error) func([]*T) {
	if cb == nil {
		panic("cb can't be nil in eventHandlerArray from parser")
	}
	return func(events []*T) {
		for _, enricher := range enrichers {
			for _, ev := range events {
				enricher(ev)
			}
		}
		cb(events)
	}
}

func (p *parser[T]) EventHandlerFunc(enrichers ...func(any) error) any {
	return p.eventHandler(p.eventCallback, enrichers...)
}

func (p *parser[T]) EventHandlerFuncArray(enrichers ...func(any) error) any {
	return p.eventHandlerArray(p.eventCallbackArray, enrichers...)
}

func (p *parser[T]) GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter {
	return &outputHelper[T]{
		TextColumnsFormatter: textcolumns.NewFormatter(p.columns.GetColumnMap(p.columnFilters...), options...),
	}
}

func (p *parser[T]) GetColumnAttributes() []columns.Attributes {
	out := make([]columns.Attributes, 0)
	for _, column := range p.columns.GetOrderedColumns(p.columnFilters...) {
		out = append(out, column.Attributes)
	}
	return out
}

func (p *parser[T]) GetColumns() any {
	return p.columns.GetColumnMap(p.columnFilters...)
}

func (p *parser[T]) GetDefaultColumns(hiddenTags ...string) []string {
	cols := make([]string, 0)
columnLoop:
	for _, column := range p.columns.GetOrderedColumns(p.columnFilters...) {
		if !column.Visible {
			continue
		}
		for _, tag := range hiddenTags {
			if column.HasTag(tag) {
				continue columnLoop
			}
		}
		cols = append(cols, column.Name)
	}
	return cols
}

func (p *parser[T]) VerifyColumnNames(columnNames []string) (valid []string, invalid []string) {
	return p.columns.VerifyColumnNames(columnNames)
}
