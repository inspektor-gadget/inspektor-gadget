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
wire the events of gadgets directly to the column formatter and use generic operations
like filtering and sorting on them.
*/
package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/filter"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/snapshotcombiner"
)

type ErrorCallback func(severity logger.Level, message string)

// Parser is the (untyped) interface used for parser
type Parser interface {
	// GetTextColumnsFormatter returns the default formatter for this columns instance
	GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter

	// GetColumnNamesAndDescription returns a map of column names to their respective descriptions
	GetColumnNamesAndDescription() map[string]string

	// GetDefaultColumns returns a list of columns that are visible by default
	GetDefaultColumns() []string

	// SetColumnFilters sets additional column filters that will be used whenever one of the other methods of this
	// interface are called. This is for example used to filter columns with information on kubernetes in a non-k8s
	// environment like local-gadget
	SetColumnFilters(...columns.ColumnFilter)

	// SetSorting sets what sorting should be applied when calling SortEntries() // TODO
	SetSorting([]string) error

	// SetFilters sets which filter to apply before emitting events downstream
	SetFilters([]string) error

	// EventHandlerFunc returns a function that accepts an instance of type *T and pushes it downstream after applying
	// enrichers and filters
	EventHandlerFunc(enrichers ...func(any) error) any
	EventHandlerFuncArray(enrichers ...func(any) error) any
	EventHandlerFuncSnapshot(key string, enrichers ...func(any) error) any

	// JSONHandlerFunc returns a function that accepts a JSON encoded event, unmarshal it into *T and pushes it
	// downstream after applying enrichers and filters
	JSONHandlerFunc(enrichers ...func(any) error) func([]byte)
	JSONHandlerFuncArray(enrichers ...func(any) error) func([]byte)

	// SetEventCallback sets the downstream callback
	SetEventCallback(eventCallback any)

	// SetErrorCallback sets the function to use whenever errors occur in this library or are received in-band
	SetErrorCallback(errorCallback ErrorCallback)

	// EnableSnapshots initializes the snapshot collector, which is able to aggregate snapshots from several sources
	// and can return (optionally cached) results on demand; used for top gadgets
	EnableSnapshots(ctx context.Context, t time.Duration, ttl int)
}

type parser[T any] struct {
	columns            *columns.Columns[T]
	sortBy             []string
	filters            []string
	filterSpec         *filter.FilterSpec[T] // TODO: filter collection(!)
	eventCallback      func(*T)
	eventCallbackArray func([]*T)
	errorCallback      ErrorCallback
	snapshotCombiner   *snapshotcombiner.SnapshotCombiner[T]
	enableSnapshots    bool
	columnFilters      []columns.ColumnFilter
}

func NewParser[T any](columns *columns.Columns[T]) Parser {
	p := &parser[T]{
		columns: columns,
	}
	return p
}

func (p *parser[T]) EnableSnapshots(ctx context.Context, interval time.Duration, ttl int) {
	if p.eventCallbackArray == nil {
		panic("EnableSnapshots needs EventCallbackArray set")
	}
	p.snapshotCombiner = snapshotcombiner.NewSnapshotCombiner[T](ttl)
	p.enableSnapshots = true
	go func() {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ticker.C:
				out, _ := p.snapshotCombiner.GetSnapshots()
				p.eventCallbackArray(out)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (p *parser[T]) SetColumnFilters(filters ...columns.ColumnFilter) {
	p.columnFilters = filters
}

func (p *parser[T]) SetErrorCallback(errorCallback ErrorCallback) {
	p.errorCallback = errorCallback
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

func (p *parser[T]) eventHandler(enrichers ...func(any) error) func(*T) {
	if p.eventCallback == nil {
		panic("set event callback before getting the eventHandler from parser")
	}
	return func(ev *T) {
		for _, enricher := range enrichers {
			enricher(ev)
		}
		if p.filterSpec != nil && !p.filterSpec.Match(ev) {
			return
		}
		p.eventCallback(ev)
	}
}

func (p *parser[T]) eventHandlerArray(enrichers ...func(any) error) func([]*T) {
	if p.eventCallbackArray == nil {
		panic("set event callback before getting the eventHandlerArray from parser")
	}
	return func(events []*T) {
		for _, enricher := range enrichers {
			for _, ev := range events {
				enricher(ev)
			}
		}

		filteredEvents := make([]*T, 0)
		if p.filterSpec != nil {
			for _, ev := range events {
				if !p.filterSpec.Match(ev) {
					continue
				}
				filteredEvents = append(filteredEvents, ev)
			}
		} else {
			filteredEvents = events
		}

		p.eventCallbackArray(filteredEvents)
	}
}

func (p *parser[T]) eventHandlerSnapshot(key string, enrichers ...func(any) error) func([]*T) {
	return func(events []*T) {
		for _, enricher := range enrichers {
			for _, ev := range events {
				enricher(ev)
			}
		}
		p.snapshotCombiner.AddSnapshot(key, events)
	}
}

func (p *parser[T]) writeErrorMessage(severity logger.Level, message string) {
	if p.errorCallback == nil {
		return
	}
	p.errorCallback(severity, message)
}

func (p *parser[T]) JSONHandlerFunc(enrichers ...func(any) error) func([]byte) {
	handler := p.eventHandler(enrichers...)
	return func(event []byte) {
		ev := new(T)
		err := json.Unmarshal(event, ev)
		if err != nil {
			p.writeErrorMessage(logger.WarnLevel, fmt.Sprintf("Error unmarshalling: %v", err))
			return
		}
		handler(ev)
	}
}

func (p *parser[T]) JSONHandlerFuncArray(enrichers ...func(any) error) func([]byte) {
	handler := p.eventHandlerArray(enrichers...)
	return func(event []byte) {
		var ev []*T
		err := json.Unmarshal(event, &ev)
		if err != nil {
			p.writeErrorMessage(logger.WarnLevel, fmt.Sprintf("Error unmarshalling: %v", err))
			return
		}
		handler(ev)
	}
}

func (p *parser[T]) EventHandlerFunc(enrichers ...func(any) error) any {
	return p.eventHandler(enrichers...)
}

func (p *parser[T]) EventHandlerFuncArray(enrichers ...func(any) error) any {
	return p.eventHandlerArray(enrichers...)
}

func (p *parser[T]) EventHandlerFuncSnapshot(key string, enrichers ...func(any) error) any {
	return p.eventHandlerSnapshot(key, enrichers...)
}

func (p *parser[T]) GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter {
	return &outputHelper[T]{
		parser:               p,
		TextColumnsFormatter: textcolumns.NewFormatter(p.columns.GetColumnMap(p.columnFilters...), options...),
	}
}

func (p *parser[T]) GetColumnNamesAndDescription() map[string]string {
	out := make(map[string]string)
	for _, column := range p.columns.GetOrderedColumns(p.columnFilters...) {
		out[column.Name] = column.Description
	}
	return out
}

func (p *parser[T]) GetDefaultColumns() []string {
	cols := make([]string, 0)
	for _, column := range p.columns.GetOrderedColumns(p.columnFilters...) {
		if !column.Visible {
			continue
		}
		cols = append(cols, column.Name)
	}
	return cols
}

func (p *parser[T]) SetSorting(sortBy []string) error {
	p.columns.VerifyColumnNames(sortBy)
	p.sortBy = sortBy
	return nil
}

func (p *parser[T]) SetFilters(filters []string) error {
	if len(filters) == 0 {
		return nil
	}

	// TODO: need to use filterCollection here to get one filterSpec from all filters
	filterSpec, err := filter.GetFilterFromString(p.columns.ColumnMap, filters[0])
	if err != nil {
		return err
	}

	p.columns.VerifyColumnNames(filters)
	p.filters = filters
	p.filterSpec = filterSpec
	return nil
}
