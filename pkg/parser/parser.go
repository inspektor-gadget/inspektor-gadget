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

	// GetDefaultColumns returns a list of columns that are visible by default.
	GetDefaultColumns() []string

	// EventHandlerFunc returns a function that accepts an instance of type *T and pushes it downstream.
	EventHandlerFunc() any
	EventHandlerFuncArray() any

	// SetEventCallback sets the downstream callback
	SetEventCallback(eventCallback any)
}

type parser[T any] struct {
	columns            *columns.Columns[T]
	eventCallback      func(*T)
	eventCallbackArray func([]*T)
}

func NewParser[T any](columns *columns.Columns[T]) Parser {
	p := &parser[T]{
		columns: columns,
	}
	return p
}

func (p *parser[T]) SetEventCallback(eventCallback any) {
	switch cb := eventCallback.(type) {
	case func(*T):
		// Typed, can be used as eventCallback directly
		p.eventCallback = cb
	case func([]*T):
		// Typed array, can be used as eventCallback directly
		p.eventCallbackArray = cb
	default:
		panic("cannot use event callback for parser")
	}
}

func (p *parser[T]) EventHandlerFunc() any {
	if p.eventCallback == nil {
		panic("cb can't be nil in eventHandler from parser")
	}
	return p.eventCallback
}

func (p *parser[T]) EventHandlerFuncArray() any {
	if p.eventCallbackArray == nil {
		panic("cb can't be nil in eventHandlerArray from parser")
	}
	return p.eventCallbackArray
}

func (p *parser[T]) GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter {
	return &outputHelper[T]{
		TextColumnsFormatter: textcolumns.NewFormatter(p.columns.GetColumnMap(), options...),
	}
}

func (p *parser[T]) GetDefaultColumns() []string {
	cols := make([]string, 0)
	for _, column := range p.columns.GetOrderedColumns() {
		if !column.Visible {
			continue
		}
		cols = append(cols, column.Name)
	}
	return cols
}
