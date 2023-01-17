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
Package columnhelpers wraps a couple of helper libraries with the intention of hiding
type information and simplifying data handling outside the gadgets. It can be used to
wire the events of gadgets directly to the column formatter and use generic operations
like filtering and sorting on them.
*/
package columnhelpers

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

// Columns is the (untyped) interface used for ColumnHelpers
type Columns interface {
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
	EventHandlerFunc(enrichers ...func(any)) any
	EventHandlerFuncArray(enrichers ...func(any)) any
	EventHandlerFuncSnapshot(key string, enrichers ...func(any)) any

	// JSONHandlerFunc returns a function that accepts a JSON encoded event, unmarshal it into *T and pushes it
	// downstream after applying enrichers and filters
	JSONHandlerFunc(enrichers ...func(any)) func([]byte)
	JSONHandlerFuncArray(enrichers ...func(any)) func([]byte)

	// SetEventCallback sets the downstream callback
	SetEventCallback(eventCallback any)
	SetEventCallbackArray(eventCallback any)

	// SetErrorCallback sets the function to use whenever errors occur in this library or are received in-band
	SetErrorCallback(errorCallback ErrorCallback)

	// EnableSnapshots initializes the snapshot collector, which is able to aggregate snapshots from several sources
	// and can return (optionally cached) results on demand; used for top gadgets
	EnableSnapshots(ctx context.Context, t time.Duration, ttl int)
}

type ColumnHelpers[T any] struct {
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

func NewColumnHelpers[T any](columns *columns.Columns[T]) Columns {
	ch := &ColumnHelpers[T]{
		columns: columns,
	}
	return ch
}

func (ch *ColumnHelpers[T]) EnableSnapshots(ctx context.Context, interval time.Duration, ttl int) {
	if ch.eventCallbackArray == nil {
		panic("EnableSnapshots needs EventCallbackArray set")
	}
	ch.snapshotCombiner = snapshotcombiner.NewSnapshotCombiner[T](ttl)
	ch.enableSnapshots = true
	go func() {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-ticker.C:
				out, _ := ch.snapshotCombiner.GetSnapshots()
				ch.eventCallbackArray(out)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (ch *ColumnHelpers[T]) SetColumnFilters(filters ...columns.ColumnFilter) {
	ch.columnFilters = filters
}

func (ch *ColumnHelpers[T]) SetErrorCallback(errorCallback ErrorCallback) {
	ch.errorCallback = errorCallback
}

func (ch *ColumnHelpers[T]) SetEventCallback(eventCallback any) {
	// Check, whether the caller wants a generic callback function (e.g. to print JSON)
	gcb, ok := eventCallback.(func(any))
	if ok {
		ch.eventCallback = func(ev *T) {
			gcb(ev)
		}
		return
	}

	// If it's non-generic, we expect it to know our type T
	cb, ok := eventCallback.(func(*T))
	if !ok {
		panic("cannot use event callback for columnhelper")
	}
	ch.eventCallback = cb
}

func (ch *ColumnHelpers[T]) SetEventCallbackArray(eventCallback any) {
	// Check, whether the caller wants a generic callback function (e.g. to print JSON)
	gcb, ok := eventCallback.(func(any))
	if ok {
		ch.eventCallbackArray = func(ev []*T) {
			gcb(ev)
		}
		return
	}

	// If it's non-generic, we expect it to know our type T
	cb, ok := eventCallback.(func([]*T))
	if !ok {
		panic("cannot use event callback for columnhelper")
	}
	ch.eventCallbackArray = cb
}

func (ch *ColumnHelpers[T]) eventHandler(enrichers ...func(any)) func(*T) {
	return func(ev *T) {
		if enrichers != nil {
			for _, enricher := range enrichers {
				enricher(ev)
			}
		}
		if ch.filterSpec != nil && !ch.filterSpec.Match(ev) {
			return
		}
		ch.eventCallback(ev)
	}
}

func (ch *ColumnHelpers[T]) eventHandlerArray(enrichers ...func(any)) func([]*T) {
	return func(events []*T) {
		if enrichers != nil {
			for _, enricher := range enrichers {
				for _, ev := range events {
					enricher(ev)
				}
			}
		}
		// TODO: Filter
		ch.eventCallbackArray(events)
	}
}

func (ch *ColumnHelpers[T]) eventHandlerSnapshot(key string, enrichers ...func(any)) func([]*T) {
	return func(events []*T) {
		if enrichers != nil {
			for _, enricher := range enrichers {
				for _, ev := range events {
					enricher(ev)
				}
			}
		}
		ch.snapshotCombiner.AddSnapshot(key, events)
	}
}

func (ch *ColumnHelpers[T]) writeErrorMessage(severity logger.Level, message string) {
	if ch.errorCallback == nil {
		return
	}
	ch.errorCallback(severity, message)
}

func (ch *ColumnHelpers[T]) JSONHandlerFunc(enrichers ...func(any)) func([]byte) {
	if ch.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from ColumnHelper")
	}
	handler := ch.eventHandler(enrichers...)
	return func(event []byte) {
		ev := new(T)
		err := json.Unmarshal(event, ev)
		if err != nil {
			ch.writeErrorMessage(logger.WarnLevel, fmt.Sprintf("Error unmarshalling: %v", err))
			return
		}
		handler(ev)
	}
}

func (ch *ColumnHelpers[T]) JSONHandlerFuncArray(enrichers ...func(any)) func([]byte) {
	if ch.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from ColumnHelper")
	}
	handler := ch.eventHandlerArray(enrichers...)
	return func(event []byte) {
		var ev []*T
		err := json.Unmarshal(event, &ev)
		if err != nil {
			ch.writeErrorMessage(logger.WarnLevel, fmt.Sprintf("Error unmarshalling: %v", err))
			return
		}
		handler(ev)
	}
}

func (ch *ColumnHelpers[T]) EventHandlerFunc(enrichers ...func(any)) any {
	if ch.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from ColumnHelper")
	}
	return ch.eventHandler(enrichers...)
}

func (ch *ColumnHelpers[T]) EventHandlerFuncArray(enrichers ...func(any)) any {
	if ch.eventCallbackArray == nil {
		panic("set event callback before getting the EventHandlerFunc from ColumnHelper")
	}
	return ch.eventHandlerArray(enrichers...)
}

func (ch *ColumnHelpers[T]) EventHandlerFuncSnapshot(key string, enrichers ...func(any)) any {
	if ch.eventCallbackArray == nil {
		panic("set event callback before getting the EventHandlerFunc from ColumnHelper")
	}
	return ch.eventHandlerSnapshot(key, enrichers...)
}

func (ch *ColumnHelpers[T]) GetTextColumnsFormatter(options ...textcolumns.Option) TextColumnsFormatter {
	return &outputHelper[T]{
		ch:                   ch,
		TextColumnsFormatter: textcolumns.NewFormatter(ch.columns.GetColumnMap(ch.columnFilters...), options...),
	}
}

func (ch *ColumnHelpers[T]) GetColumnNamesAndDescription() map[string]string {
	out := make(map[string]string)
	for _, column := range ch.columns.GetOrderedColumns(ch.columnFilters...) {
		out[column.Name] = column.Description
	}
	return out
}

func (ch *ColumnHelpers[T]) GetDefaultColumns() []string {
	cols := make([]string, 0)
	for _, column := range ch.columns.GetOrderedColumns(ch.columnFilters...) {
		if !column.Visible {
			continue
		}
		cols = append(cols, column.Name)
	}
	return cols
}

func (ch *ColumnHelpers[T]) SetSorting(sortBy []string) error {
	ch.columns.VerifyColumnNames(sortBy)
	ch.sortBy = sortBy
	return nil
}

func (ch *ColumnHelpers[T]) SetFilters(filters []string) error {
	if len(filters) == 0 {
		return nil
	}

	// TODO: need to use filterCollection here to get one filterSpec from all filters
	filterSpec, err := filter.GetFilterFromString(ch.columns.ColumnMap, filters[0])
	if err != nil {
		return err
	}

	ch.columns.VerifyColumnNames(filters)
	ch.filters = filters
	ch.filterSpec = filterSpec
	return nil
}
