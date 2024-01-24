// Copyright 2024 The Inspektor Gadget authors
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

package datasource

import (
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type (
	data  api.GadgetData
	field api.Field
)

func (*data) private() {}

func (f *field) ReflectType() reflect.Type {
	switch Kind(f.Type) {
	default:
		return nil
	case Int8:
		return reflect.TypeOf(int8(0))
	case Int16:
		return reflect.TypeOf(int16(0))
	case Int32:
		return reflect.TypeOf(int32(0))
	case Int64:
		return reflect.TypeOf(int64(0))
	case Uint8:
		return reflect.TypeOf(uint8(0))
	case Uint16:
		return reflect.TypeOf(uint16(0))
	case Uint32:
		return reflect.TypeOf(uint32(0))
	case Uint64:
		return reflect.TypeOf(uint64(0))
	case Float32:
		return reflect.TypeOf(float32(0))
	case Float64:
		return reflect.TypeOf(float64(0))
	case Bool:
		return reflect.TypeOf(false)
	case String:
		return reflect.TypeOf("")
	}
}

type dataSource struct {
	name string
	id   uint32

	dType Type
	dPool sync.Pool

	// keeps information on registered fields
	fields   []*field
	fieldMap map[string]*field

	payloadCount uint32

	requestedFields map[string]bool

	subscriptions []*subscription

	requested bool

	lock sync.RWMutex
}

func newDataSource(t Type, name string) *dataSource {
	return &dataSource{
		name:            name,
		dType:           t,
		requestedFields: make(map[string]bool),
		fieldMap:        make(map[string]*field),
	}
}

func New(t Type, name string) DataSource {
	ds := newDataSource(t, name)
	ds.registerPool()
	return ds
}

func NewFromAPI(in *api.DataSource) (DataSource, error) {
	ds := newDataSource(Type(in.Type), in.Name)
	for _, f := range in.Fields {
		ds.fields = append(ds.fields, (*field)(f))
		ds.fieldMap[f.Name] = (*field)(f)
	}
	ds.registerPool()
	// TODO: add more checks / validation
	return ds, nil
}

func (ds *dataSource) registerPool() {
	ds.dPool.New = func() any {
		d := &data{
			Payload: make([][]byte, ds.payloadCount),
		}
		for i := range d.Payload {
			d.Payload[i] = make([]byte, 0)
		}
		return d
	}
}

func (ds *dataSource) Name() string {
	return ds.name
}

func (ds *dataSource) Type() Type {
	return ds.dType
}

func (ds *dataSource) NewData() Data {
	return ds.dPool.Get().(Data)
}

// AddStaticFields adds a statically sized container for fields to the payload and returns an accessor for the
// container; if you want to access individual fields, get them from the DataSource directly
func (ds *dataSource) AddStaticFields(size uint32, fields Fields) (FieldAccessor, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	idx := ds.payloadCount

	// temporary write to newFields to not write to ds.fields in case of errors
	var newFields []*field

	parentOffset := len(ds.fields)

	for _, f := range fields {
		if _, ok := ds.fieldMap[f.FieldName()]; ok {
			return nil, fmt.Errorf("field %q already exists", f.FieldName())
		}
		nf := &field{
			Name:         f.FieldName(),
			Index:        uint32(len(ds.fields) + len(newFields)),
			PayloadIndex: idx,
			Flags:        FieldFlagStaticMember.Uint32(),
		}
		if s, ok := f.(StaticField); ok {
			nf.Size = s.FieldSize()
			nf.Offs = s.FieldOffset()
		} else {
			return nil, fmt.Errorf("field %q is not statically sized or does not implement StaticField", nf.Name)
		}
		if s, ok := f.(TypedField); ok {
			nf.Type = uint32(s.FieldType())
		}
		if tagger, ok := f.(TaggedField); ok {
			nf.Tags = tagger.FieldTags()
		}
		if s, ok := f.(FlaggedField); ok {
			nf.Flags |= uint32(s.FieldFlags())
		}
		if s, ok := f.(ParentedField); ok {
			parent := s.FieldParent()
			if parent >= 0 {
				nf.Parent = uint32(parent + parentOffset)                          // TODO: validate?
				nf.Flags |= FieldFlagHasParent.Uint32() | FieldFlagHidden.Uint32() // default to hide subfields
			}
		}

		if nf.Offs+nf.Size > size {
			return nil, fmt.Errorf("field %q exceeds size of container (offs %d, size %d, container size %d)", nf.Name, nf.Offs, nf.Size, size)
		}
		newFields = append(newFields, nf)
	}

	ds.fields = append(ds.fields, newFields...)

	for _, f := range newFields {
		ds.fieldMap[f.Name] = f
	}

	ds.payloadCount++

	return &fieldAccessor{ds: ds, f: &field{
		PayloadIndex: idx,
		Size:         size,
	}}, nil
}

func (ds *dataSource) AddField(name string, opts ...FieldOption) (FieldAccessor, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	if _, ok := ds.fieldMap[name]; ok {
		return nil, fmt.Errorf("field %q already exists", name)
	}

	nf := &field{
		Name:  name,
		Index: uint32(len(ds.fields)),
		Type:  uint32(Slice),
	}
	for _, opt := range opts {
		opt(nf)
	}

	// Reserve new payload for non-empty fields
	if !FieldFlagEmpty.In(nf.Flags) {
		nf.PayloadIndex = ds.payloadCount
		ds.payloadCount++
	}

	ds.fields = append(ds.fields, nf)
	ds.fieldMap[nf.Name] = nf
	return &fieldAccessor{ds: ds, f: nf}, nil
}

func (ds *dataSource) GetField(name string) FieldAccessor {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	f, ok := ds.fieldMap[name]
	if !ok {
		return nil
	}
	return &fieldAccessor{ds: ds, f: f}
}

func (ds *dataSource) GetFieldsWithTag(tag ...string) []FieldAccessor {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	res := make([]FieldAccessor, 0)
	for _, f := range ds.fields {
		for _, t := range tag {
			if slices.Contains(f.Tags, t) {
				res = append(res, &fieldAccessor{ds: ds, f: f})
			}
		}
	}
	return res
}

func (ds *dataSource) Subscribe(fn DataFunc, priority int) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	if fn == nil {
		return
	}
	ds.subscriptions = append(ds.subscriptions, &subscription{
		priority: priority,
		fn:       fn,
	})
	sort.SliceStable(ds.subscriptions, func(i, j int) bool {
		return ds.subscriptions[i].priority < ds.subscriptions[j].priority
	})
}

func (ds *dataSource) EmitAndRelease(d Data) error {
	defer ds.dPool.Put(d)
	for _, sub := range ds.subscriptions {
		err := sub.fn(ds, d)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ds *dataSource) Release(d Data) {
	ds.dPool.Put(d)
}

func (ds *dataSource) ReportLostData(ctr uint64) {
	// TODO
}

func (ds *dataSource) IsRequestedField(fieldName string) bool {
	return true
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return ds.requestedFields[fieldName]
}

func (ds *dataSource) Dump(xd Data, wr io.Writer) {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	d := xd.(*data)
	for _, f := range ds.fields {
		if f.Offs+f.Size > uint32(len(d.Payload[f.PayloadIndex])) {
			fmt.Fprintf(wr, "%s (%d): ! invalid size\n", f.Name, f.Size)
			continue
		}
		if f.Offs > 0 || f.Size > 0 {
			fmt.Fprintf(wr, "%s (%d) [%s]: %v\n", f.Name, f.Size, strings.Join(f.Tags, " "), d.Payload[f.PayloadIndex][f.Offs:f.Offs+f.Size])
		} else {
			fmt.Fprintf(wr, "%s (%d) [%s]: %v\n", f.Name, f.Size, strings.Join(f.Tags, " "), d.Payload[f.PayloadIndex])
		}
	}
}

func (ds *dataSource) Fields() []*api.Field {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	res := make([]*api.Field, 0, len(ds.fields))
	for _, f := range ds.fields {
		res = append(res, (*api.Field)(f))
	}
	return res
}

func (ds *dataSource) IsRequested() bool {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return ds.requested
}
