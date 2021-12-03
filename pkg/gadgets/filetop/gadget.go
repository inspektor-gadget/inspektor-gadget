// Copyright 2019-2021 The Inspektor Gadget authors
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

package filetop

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	filetoptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

const (
	MAX_ROWS_DEFAULT  = 20
	INTERVAL_DEFAULT  = 1
	SORT_BY_DEFAULT   = types.RBYTES
	ALL_FILES_DEFAULT = false
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
	tracer  *filetoptracer.Tracer
}

type TraceFactory struct {
	gadgets.BaseFactory
}

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	t := `filetop shows reads and writes by file, with container details.

The following parameters are supported:
 - interval: Output interval, in seconds. (default %d)
 - max_rows: Maximum rows to print. (default %d)
 - sort: The field to sort the results by (%s). (default %s)`
	return fmt.Sprintf(t, INTERVAL_DEFAULT, MAX_ROWS_DEFAULT,
		strings.Join(types.SortBySlice, ","), SORT_BY_DEFAULT)
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Stream": {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.tracer != nil {
		trace.tracer.Stop()
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			resolver: f.Resolver,
		}
	}

	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start filetop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop filetop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		gadgets.CleanupTraceStatus(trace)
		trace.Status.State = "Started"
		return
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	maxRows := MAX_ROWS_DEFAULT
	intervalSeconds := INTERVAL_DEFAULT
	sortBy := SORT_BY_DEFAULT
	allFiles := ALL_FILES_DEFAULT

	if trace.Spec.Parameters != nil {
		params := trace.Spec.Parameters
		var err error

		if val, ok := params["max_rows"]; ok {
			maxRows, err = strconv.Atoi(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for ouput_rows", val)
				return
			}
		}

		if val, ok := params["interval"]; ok {
			intervalSeconds, err = strconv.Atoi(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for interval", val)
				return
			}
		}

		if val, ok := params["sortby"]; ok {
			sortBy, err = types.ParseSortBy(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for sortby", val)
				return
			}
		}

		if val, ok := params["all_files"]; ok {
			allFiles, err = strconv.ParseBool(val)
			if err != nil {
				gadgets.CleanupTraceStatus(trace)
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for all_files", val)
				return
			}
		}
	}

	config := &filetoptracer.Config{
		AllFiles:   allFiles,
		MaxRows:    maxRows,
		Interval:   time.Second * time.Duration(intervalSeconds),
		SortBy:     sortBy,
		MountnsMap: gadgets.TracePinPath(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
		Node:       trace.Spec.Node,
	}

	statsCallback := func(stats []types.Stats) {
		ev := types.Event{
			Node:  trace.Spec.Node,
			Stats: stats,
		}

		r, err := json.Marshal(ev)
		if err != nil {
			log.Warnf("Gadget %s: Failed to marshall event: %s", trace.Spec.Gadget, err)
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	errorCallback := func(err error) {
		ev := types.Event{
			Error: fmt.Sprintf("Gadget failed with: %v", err),
			Node:  trace.Spec.Node,
		}
		r, err := json.Marshal(&ev)
		if err != nil {
			log.Warnf("Gadget %s: Failed to marshall event: %s", trace.Spec.Gadget, err)
			return
		}
		t.resolver.PublishEvent(traceName, string(r))
	}

	tracer, err := filetoptracer.NewTracer(config, t.resolver, statsCallback, errorCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
		return
	}

	t.tracer = tracer
	t.started = true

	gadgets.CleanupTraceStatus(trace)
	trace.Status.State = "Started"
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Stop()
	t.tracer = nil
	t.started = false

	gadgets.CleanupTraceStatus(trace)
	trace.Status.State = "Stopped"
}
