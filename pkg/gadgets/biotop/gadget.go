// Copyright 2019-2022 The Inspektor Gadget authors
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

package biotop

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	biotoptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/biotop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biotop/types"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
)

type Trace struct {
	resolver gadgets.Resolver

	started bool
	tracer  *biotoptracer.Tracer
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
	t := `biotop shows command generating block I/O, with container details.

The following parameters are supported:
 - %s: Output interval, in seconds. (default %d)
 - %s: Maximum rows to print. (default %d)
 - %s: The field to sort the results by (%s). (default %s)`
	return fmt.Sprintf(t, types.IntervalParam, types.IntervalDefault,
		types.MaxRowsParam, types.MaxRowsDefault,
		types.SortByParam, strings.Join(types.SortBySlice, ","), types.SortByDefault)
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
			Doc: "Start biotop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
		},
		"stop": {
			Doc: "Stop biotop gadget",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
		},
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.State = "Started"
		return
	}

	traceName := gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)

	maxRows := types.MaxRowsDefault
	intervalSeconds := types.IntervalDefault
	sortBy := types.SortByDefault

	if trace.Spec.Parameters != nil {
		params := trace.Spec.Parameters
		var err error

		if val, ok := params[types.MaxRowsParam]; ok {
			maxRows, err = strconv.Atoi(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %q", val, types.MaxRowsParam)
				return
			}
		}

		if val, ok := params[types.IntervalParam]; ok {
			intervalSeconds, err = strconv.Atoi(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %q", val, types.IntervalParam)
				return
			}
		}

		if val, ok := params[types.SortByParam]; ok {
			sortBy, err = types.ParseSortBy(val)
			if err != nil {
				trace.Status.OperationError = fmt.Sprintf("%q is not valid for %q", val, types.SortByParam)
				return
			}
		}
	}

	mountNsMap, err := t.resolver.TracerMountNsMap(traceName)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to find tracer's mount ns map: %s", err)
		return
	}
	config := &biotoptracer.Config{
		MaxRows:    maxRows,
		Interval:   time.Second * time.Duration(intervalSeconds),
		SortBy:     sortBy,
		MountnsMap: mountNsMap,
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

	tracer, err := biotoptracer.NewTracer(config, t.resolver, statsCallback, errorCallback)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("failed to create tracer: %s", err)
		return
	}

	t.tracer = tracer
	t.started = true

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

	trace.Status.State = "Stopped"
}
