// Copyright 2023 The Inspektor Gadget authors
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

package prometheus

import (
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type key string

const (
	valuekey key = "pkey"
)

// stubEvent is shared by both stub gadgets just to keep it simpler
type stubEvent struct {
	Comm     string  `json:"comm,omitempty" column:"comm"`
	Uid      uint32  `json:"uid,omitempty" column:"uid"`
	IntVal   uint32  `json:"intval,omitempty" column:"intval"`
	FloatVal float32 `json:"floatval,omitempty" column:"floatval"`
}

// stubTracer is a fake tracer gadget used for testing
type stubTracer struct {
	eventCallback func(ev *stubEvent)
}

func (t *stubTracer) Name() string {
	return "stubtracer"
}

func (t *stubTracer) Description() string {
	return "fake tracer gadget"
}

func (t *stubTracer) Category() string {
	return gadgets.CategoryTrace
}

func (t *stubTracer) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (t *stubTracer) ParamDescs() params.ParamDescs {
	return nil
}

func (t *stubTracer) Parser() parser.Parser {
	cols := columns.MustCreateColumns[stubEvent]()
	return parser.NewParser(cols)
}

func (t *stubTracer) EventPrototype() any {
	return &stubEvent{}
}

func (t *stubTracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *stubEvent))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *stubTracer) Run(gadgetCtx gadgets.GadgetContext) error {
	for _, ev := range testEvents {
		t.eventCallback(ev)
	}

	ctx := gadgetCtx.Context()

	// Tell the caller test that events were generated
	if val := ctx.Value(valuekey); val != nil {
		wg := val.(*sync.WaitGroup)
		wg.Done()
	}

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *stubTracer) NewInstance() (gadgets.Gadget, error) {
	// stubTracer is both the GadgetDesc and the Gadget implementation. We can keep those
	// separated but there is not any reason to complicate this further.
	return &stubTracer{}, nil
}

/*** stub snapshotter ***/
type stubSnapshotter struct {
	eventCallback func(ev []*stubEvent)
}

func (t *stubSnapshotter) Name() string {
	return "stubsnapshotter"
}

func (t *stubSnapshotter) Description() string {
	return "fake snapshotter gadget"
}

func (t *stubSnapshotter) Category() string {
	return gadgets.CategorySnapshot
}

func (t *stubSnapshotter) Type() gadgets.GadgetType {
	return gadgets.TypeOneShot
}

func (t *stubSnapshotter) ParamDescs() params.ParamDescs {
	return nil
}

func (t *stubSnapshotter) Parser() parser.Parser {
	cols := columns.MustCreateColumns[stubEvent]()
	return parser.NewParser(cols)
}

func (t *stubSnapshotter) EventPrototype() any {
	return &stubEvent{}
}

func (t *stubSnapshotter) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*stubEvent))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *stubSnapshotter) Run(gadgetCtx gadgets.GadgetContext) error {
	t.eventCallback(testEvents)

	ctx := gadgetCtx.Context()

	// Tell the caller test that events were generated
	if val := ctx.Value(valuekey); val != nil {
		wg := val.(*sync.WaitGroup)
		wg.Done()
	}

	return nil
}

func (t *stubSnapshotter) NewInstance() (gadgets.Gadget, error) {
	// stubSnapshotter is both the GadgetDesc and the Gadget implementation. We can keep those
	// separated but there is not any reason to complicate this further.
	return &stubSnapshotter{}, nil
}

func init() {
	gadgetregistry.Register(&stubTracer{})
	gadgetregistry.Register(&stubSnapshotter{})
}
