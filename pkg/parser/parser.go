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
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/filter"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/snapshotcombiner"
)

type LogCallback func(severity logger.Level, fmt string, params ...any)

// Parser is the (untyped) interface used for parser
type Parser interface {
	// GetTextColumnsFormatter returns the default formatter for this columns instance
	GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter

	// GetColumnNamesAndDescription returns a map of column names to their respective descriptions
	GetColumnNamesAndDescription() map[string]string

	// GetDefaultColumns returns a list of columns that are visible by default
	GetDefaultColumns() []string

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

	// SetSorting sets what sorting should be applied when calling SortEntries() // TODO
	SetSorting([]string) error

	// SetFilters sets which filter to apply before emitting events downstream
	SetFilters([]string) error

	// EventHandlerFunc returns a function that accepts an instance of type *T and pushes it downstream after applying
	// enrichers and filters
	EventHandlerFunc(enrichers ...func(any) error) any
	EventHandlerFuncArray(enrichers ...func(any) error) any

	// JSONHandlerFunc returns a function that accepts a JSON encoded event, unmarshal it into *T and pushes it
	// downstream after applying enrichers and filters
	JSONHandlerFunc(enrichers ...func(any) error) func([]byte)
	JSONHandlerFuncArray(key string, enrichers ...func(any) error) func([]byte)

	// SetEventCallback sets the downstream callback
	SetEventCallback(eventCallback any)

	// SetLogCallback sets the function to use to send log messages
	SetLogCallback(logCallback LogCallback)

	// EnableSnapshots initializes the snapshot combiner, which is able to aggregate snapshots from several sources
	// and can return (optionally cached) results on demand; used for top gadgets
	EnableSnapshots(ctx context.Context, t time.Duration, ttl int)

	// EnableCombiner initializes the event combiner, which aggregates events from all sources; used for snapshot gadgets.
	// Events are released by calling Flush().
	EnableCombiner()

	// Flush sends the events downstream that were collected after EnableCombiner() was called.
	Flush()
}

type parser[T any] struct {
	columns            *columns.Columns[T]
	sortBy             []string
	sortSpec           *sort.ColumnSorterCollection[T]
	filters            []string
	filterSpecs        *filter.FilterSpecs[T] // TODO: filter collection(!)
	eventCallback      func(*T)
	eventCallbackArray func([]*T)
	logCallback        LogCallback
	snapshotCombiner   *snapshotcombiner.SnapshotCombiner[T]
	columnFilters      []columns.ColumnFilter

	// event combiner related fields
	eventCombinerEnabled bool
	combinedEvents       []*T
	mu                   sync.Mutex
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

func (p *parser[T]) EnableCombiner() {
	if p.eventCallbackArray == nil {
		panic("eventCallbackArray has to be set before using EnableCombiner()")
	}

	p.eventCombinerEnabled = true
	p.combinedEvents = []*T{}
}

func (p *parser[T]) Flush() {
	p.eventCallbackArray(p.combinedEvents)
}

func (p *parser[T]) SetColumnFilters(filters ...columns.ColumnFilter) {
	p.columnFilters = filters
}

func (p *parser[T]) SetLogCallback(logCallback LogCallback) {
	p.logCallback = logCallback
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
		if p.filterSpecs != nil && !p.filterSpecs.MatchAll(ev) {
			return
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
		if p.filterSpecs != nil {
			filteredEvents := make([]*T, 0, len(events))
			for _, event := range events {
				if !p.filterSpecs.MatchAll(event) {
					continue
				}
				filteredEvents = append(filteredEvents, event)
			}
			events = filteredEvents
		}
		if p.sortSpec != nil {
			p.sortSpec.Sort(events)
		}
		cb(events)
	}
}

func (p *parser[T]) writeLogMessage(severity logger.Level, fmt string, params ...any) {
	if p.logCallback == nil {
		return
	}
	p.logCallback(severity, fmt, params)
}

func (p *parser[T]) combineEventsArrayCallback(events []*T) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.combinedEvents = append(p.combinedEvents, events...)
}

func (p *parser[T]) combineEventsCallback(event *T) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.combinedEvents = append(p.combinedEvents, event)
}

func (p *parser[T]) JSONHandlerFunc(enrichers ...func(any) error) func([]byte) {
	cb := p.eventCallback
	if p.eventCombinerEnabled {
		cb = p.combineEventsCallback
	}

	handler := p.eventHandler(cb, enrichers...)
	return func(event []byte) {
		ev := new(T)
		err := json.Unmarshal(event, ev)
		if err != nil {
			p.writeLogMessage(logger.WarnLevel, "unmarshalling: %s", err)
			return
		}
		handler(ev)
	}
}

func (p *parser[T]) JSONHandlerFuncArray(key string, enrichers ...func(any) error) func([]byte) {
	cb := p.eventCallbackArray
	if p.eventCombinerEnabled {
		cb = p.combineEventsArrayCallback
	} else if p.snapshotCombiner != nil {
		cb = func(events []*T) {
			p.snapshotCombiner.AddSnapshot(key, events)
		}
	}

	handler := p.eventHandlerArray(cb, enrichers...)

	return func(event []byte) {
		var ev []*T
		err := json.Unmarshal(event, &ev)
		if err != nil {
			p.writeLogMessage(logger.WarnLevel, "unmarshalling: %s", err)
			return
		}
		handler(ev)
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

func (p *parser[T]) GetColumns() any {
	return p.columns.GetColumnMap(p.columnFilters...)
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

func (p *parser[T]) VerifyColumnNames(columnNames []string) (valid []string, invalid []string) {
	return p.columns.VerifyColumnNames(columnNames)
}

func (p *parser[T]) SetSorting(sortBy []string) error {
	_, invalid := p.columns.VerifyColumnNames(sortBy)
	if len(invalid) > 0 {
		return fmt.Errorf("invalid columns to sort by: %v", invalid)
	}
	p.sortSpec = sort.Prepare(p.columns.ColumnMap, sortBy)
	p.sortBy = sortBy
	return nil
}

func (p *parser[T]) SetFilters(filters []string) error {
	if len(filters) == 0 {
		return nil
	}

	filterSpecs, err := filter.GetFiltersFromStrings(p.columns.ColumnMap, filters)
	if err != nil {
		return err
	}

	p.filters = filters
	p.filterSpecs = filterSpecs
	return nil
}
