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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	filetoptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

type Trace struct {
	helpers gadgets.GadgetHelpers

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
	cols := columns.MustCreateColumns[types.Stats]()

	t := `filetop shows reads and writes by file, with container details.

The following parameters are supported:
 - %s: Output interval, in seconds. (default %d)
 - %s: Maximum rows to print. (default %d)
 - %s: The field to sort the results by (%s). (default %s)
 - %s: Show all files. (default %v, i.e. show regular files only)`
	return fmt.Sprintf(t, types.IntervalParam, types.IntervalDefault,
		types.MaxRowsParam, types.MaxRowsDefault,
		types.SortByParam, strings.Join(cols.GetColumnNames(), ","), strings.Join(types.SortByDefault, ","),
		types.AllFilesParam, types.AllFilesDefault)
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStream: {},
	}
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.tracer != nil {
		trace.tracer.Stop()
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			helpers: f.Helpers,
		}
	}

	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start filetop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop filetop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		return
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	maxRows := types.MaxRowsDefault
	intervalSeconds := types.IntervalDefault
	sortBy := types.SortByDefault
	allFiles := types.AllFilesDefault

	if trace.Spec.Parameters != nil {
		params := trace.Spec.Parameters
		var err error

		if val, ok := params[types.MaxRowsParam]; ok {
			maxRows, err = strconv.Atoi(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %s: %v", val, types.MaxRowsParam, err)
				return
			}
		}

		if val, ok := params[types.IntervalParam]; ok {
			intervalSeconds, err = strconv.Atoi(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %s: %v", val, types.IntervalParam, err)
				return
			}
		}

		if val, ok := params[types.SortByParam]; ok {
			sortByColumns := strings.Split(params[types.SortByParam], ",")
			sortBy = make([]string, len(sortByColumns))

			cols := columns.MustCreateColumns[types.Stats]()
			for i, col := range sortByColumns {
				colToTest := col
				if len(col) > 0 && col[0] == '-' {
					colToTest = colToTest[1:]
				}
				_, ok := cols.GetColumn(colToTest)
				if !ok {
					trace.Status.OperationError = fmt.Sprintf("%q is not valid for %q", val, types.SortByParam)
					return
				}
				sortBy[i] = col
			}
		}

		if val, ok := params[types.AllFilesParam]; ok {
			allFiles, err = strconv.ParseBool(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %s: %v", val, types.AllFilesParam, err)
				return
			}
		}
	}

	mountNsMap, err := t.helpers.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}

	config := &filetoptracer.Config{
		AllFiles:   allFiles,
		MaxRows:    maxRows,
		Interval:   time.Second * time.Duration(intervalSeconds),
		SortBy:     sortBy,
		MountnsMap: mountNsMap,
	}

	eventCallback := func(ev *types.Event) {
		r, err := json.Marshal(ev)
		if err != nil {
			log.Warnf("Gadget %s: Failed to marshall event: %s", trace.Spec.Gadget, err)
			return
		}
		t.helpers.PublishEvent(traceName, string(r))
	}

	tracer, err := filetoptracer.NewTracer(config, t.helpers, eventCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
		return
	}

	t.tracer = tracer
	t.started = true

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	t.tracer.Stop()
	t.tracer = nil
	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
