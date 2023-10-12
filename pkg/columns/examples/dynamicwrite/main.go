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

package main

import (
	"fmt"
	"os"
	"reflect"
	"unsafe"

	"sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
)

type Field struct {
	Name   string
	Offset int
	Size   int
	Type   string
	Index  int
}

type Event struct {
	blobs [][]byte
}

type Definition struct {
	Fields []Field `yaml:"fields"`
}

type FieldWriter[T any] func(event *Event, value T)

type API struct {
	columns             *columns.Columns[Event]
	curOffset           uintptr
	additionalBlobCount int
}

func NewAPI() *API {
	return &API{
		columns: columns.MustCreateColumns[Event](),
	}
}

func (a *API) NewEvent() *Event {
	// Reserve space
	ev := &Event{blobs: make([][]byte, 1+a.additionalBlobCount)}
	ev.blobs[0] = make([]byte, a.curOffset)
	return ev
}

// AddStaticField must be called in-order and without gaps in this demo
func AddStaticField[T any](a *API, name string) (FieldWriter[T], error) {
	t := reflect.TypeOf(*new(T))
	err := a.columns.AddFields([]columns.DynamicField{
		{
			Attributes: &columns.Attributes{
				Name: name,
			},
			Type:   t,
			Offset: a.curOffset,
		},
	}, func(e *Event) unsafe.Pointer {
		return unsafe.Pointer(&e.blobs[0][0])
	})
	if err != nil {
		return nil, err
	}
	a.curOffset += t.Size()
	col, ok := a.columns.GetColumn(name)
	if !ok {
		panic("nah")
	}
	writer := columns.SetFieldFunc[T, Event](col)
	return func(event *Event, value T) {
		writer(event, value)
	}, nil
}

func AddString(a *API, name string) (FieldWriter[string], error) {
	err := a.columns.AddFields([]columns.DynamicField{
		{
			Attributes: &columns.Attributes{
				Name: name,
			},
			Type:   reflect.TypeOf(string("")),
			Offset: 0,
		},
	}, func(e *Event) unsafe.Pointer {
		return unsafe.Pointer(&e.blobs[1])
	})
	if err != nil {
		return nil, err
	}
	a.additionalBlobCount++
	blobIndex := a.additionalBlobCount
	return func(event *Event, value string) {
		event.blobs[blobIndex] = []byte(value)
	}, nil
}

func main() {
	api := NewAPI()

	definition := &Definition{}

	def, _ := os.ReadFile("./def.yaml")
	err := yaml.Unmarshal(def, &definition)
	if err != nil {
		panic(err)
	}

	// Register stuff from BTF
	for _, f := range definition.Fields {
		switch f.Type {
		case "uint32":
			_, err := AddStaticField[uint32](api, f.Name)
			if err != nil {
				panic(err)
			}
		}
	}

	// Register from operator
	swr, err := AddString(api, "operatorsays")
	if err != nil {
		panic(err)
	}
	// TODO: update definition (add this field)

	// Register from wasm
	wwr, err := AddStaticField[uint64](api, "wasmnum")
	if err != nil {
		panic(err)
	}
	// TODO: update definition (add this field)

	// Now demo with an event
	ev := api.NewEvent()

	// From eBPF we can simply copy to the start of the first blob
	copy(ev.blobs[0], []byte{
		1, 0, 0, 0,
		2, 0, 0, 0,
	})

	swr(ev, "Operator says hi!")

	wwr(ev, 65535)

	fmt.Printf("%+v\n", ev.blobs)

	// Now read
	col, _ := api.columns.GetColumn("Demo")
	demoff := columns.GetFieldFunc[uint32, Event](col)
	fmt.Printf("Demo: %d\n", demoff(ev))

	col, _ = api.columns.GetColumn("Foo")
	fooff := columns.GetFieldFunc[uint32, Event](col)
	fmt.Printf("Foo: %d\n", fooff(ev))

	col, _ = api.columns.GetColumn("operatorsays")
	opff := columns.GetFieldFuncExt[[]byte, Event](col, true)
	fmt.Printf("Operator: %+v\n", opff(ev))

	col, _ = api.columns.GetColumn("wasmnum")
	wasmff := columns.GetFieldFunc[uint64, Event](col)
	fmt.Printf("WASM: %d\n", wasmff(ev))

	// Now as JSON
	jf := json.NewFormatter(api.columns.GetColumnMap())
	fmt.Printf("JSON: %s\n", jf.FormatEntry(ev))
}
