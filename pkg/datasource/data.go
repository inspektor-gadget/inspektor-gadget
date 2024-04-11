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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type data api.GadgetData

type dataElement [][]byte

type dataArray struct {
	ds *dataSource
	*api.GadgetDataArray
}

type (
	field api.Field
)

func (*data) private() {}

func (d *data) payloads() [][]byte {
	return d.Payloads
}

func (d dataElement) private() {
}

func (d dataElement) payloads() [][]byte {
	return d
}

func (f *field) ReflectType() reflect.Type {
	switch f.Kind {
	default:
		return nil
	case api.Kind_Int8:
		return reflect.TypeOf(int8(0))
	case api.Kind_Int16:
		return reflect.TypeOf(int16(0))
	case api.Kind_Int32:
		return reflect.TypeOf(int32(0))
	case api.Kind_Int64:
		return reflect.TypeOf(int64(0))
	case api.Kind_Uint8:
		return reflect.TypeOf(uint8(0))
	case api.Kind_Uint16:
		return reflect.TypeOf(uint16(0))
	case api.Kind_Uint32:
		return reflect.TypeOf(uint32(0))
	case api.Kind_Uint64:
		return reflect.TypeOf(uint64(0))
	case api.Kind_Float32:
		return reflect.TypeOf(float32(0))
	case api.Kind_Float64:
		return reflect.TypeOf(float64(0))
	case api.Kind_Bool:
		return reflect.TypeOf(false)
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

	tags        []string
	annotations map[string]string

	payloadCount uint32

	requestedFields map[string]bool

	subscriptionsSingle   []*subscription
	subscriptionsElements []*subscription
	subscriptionsArray    []*subscriptionArray

	requested bool

	byteOrder binary.ByteOrder
	lock      sync.RWMutex
}

func newDataSource(t Type, name string) *dataSource {
	return &dataSource{
		name:            name,
		dType:           t,
		requestedFields: make(map[string]bool),
		fieldMap:        make(map[string]*field),
		byteOrder:       binary.NativeEndian,
		tags:            make([]string, 0),
		annotations:     map[string]string{},
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
		if !FieldFlagUnreferenced.In(f.Flags) {
			ds.fieldMap[f.Name] = (*field)(f)
		}
	}
	if in.Flags&api.DataSourceFlagsBigEndian != 0 {
		ds.byteOrder = binary.BigEndian
	} else {
		ds.byteOrder = binary.LittleEndian
	}
	ds.registerPool()
	// TODO: add more checks / validation
	return ds, nil
}

func (ds *dataSource) registerPool() {
	ds.dPool.New = func() any {
		d := &api.GadgetData{}
		return (*data)(d)
	}
}

func (ds *dataSource) Name() string {
	return ds.name
}

func (ds *dataSource) Type() Type {
	return ds.dType
}

func (ds *dataSource) NewData() DataSingle {
	d := ds.dPool.Get().(*data)
	(*api.GadgetData)(d).Reset()
	d.Payloads = make([][]byte, ds.payloadCount)
	for i := uint32(0); i < ds.payloadCount; i++ {
		d.Payloads[i] = make([]byte, 0)
	}
	return d
}

func (ds *dataSource) NewDataArray() DataArray {
	return dataArray{
		ds:              ds,
		GadgetDataArray: &api.GadgetDataArray{},
	}
}

func (ds *dataSource) ByteOrder() binary.ByteOrder {
	return ds.byteOrder
}

func resolveNames(id uint32, fields []*field, parentOffset uint32) (string, error) {
	if id >= uint32(len(fields)) {
		return "", errors.New("invalid id")
	}
	out := ""
	if FieldFlagHasParent.In(fields[id].Flags) {
		p, err := resolveNames(fields[id].Parent-parentOffset, fields, parentOffset)
		if err != nil {
			return "", errors.New("parent not found")
		}
		out = p + "."
	}
	out += fields[id].Name
	return out, nil
}

// AddStaticFields adds a statically sized container for fields to the payload and returns an accessor for the
// container; if you want to access individual fields, get them from the DataSource directly
func (ds *dataSource) AddStaticFields(size uint32, fields []StaticField) (FieldAccessor, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	idx := ds.payloadCount

	// temporary write to newFields to not write to ds.fields in case of errors
	newFields := make([]*field, 0, len(fields))

	parentOffset := len(ds.fields)
	parentFields := make(map[int]struct{})
	checkParents := make(map[*field]struct{})

	for _, f := range fields {
		fieldName := f.FieldName()
		if _, ok := ds.fieldMap[fieldName]; ok {
			return nil, fmt.Errorf("field %q already exists", fieldName)
		}
		nf := &field{
			Name:         fieldName,
			Index:        uint32(len(ds.fields) + len(newFields)),
			PayloadIndex: idx,
			Flags:        FieldFlagStaticMember.Uint32(),
		}
		nf.Size = f.FieldSize()
		nf.Offs = f.FieldOffset()
		if nf.Offs+nf.Size > size {
			return nil, fmt.Errorf("field %q exceeds size of container (offs %d, size %d, container size %d)", nf.Name, nf.Offs, nf.Size, size)
		}
		if s, ok := f.(TypedField); ok {
			nf.Kind = s.FieldType()
		}
		if tagger, ok := f.(TaggedField); ok {
			nf.Tags = tagger.FieldTags()
		}
		if s, ok := f.(FlaggedField); ok {
			nf.Flags |= uint32(s.FieldFlags())
		}
		if s, ok := f.(AnnotatedField); ok {
			nf.Annotations = s.FieldAnnotations()
		}
		if s, ok := f.(ParentedField); ok {
			parent := s.FieldParent()
			if parent >= 0 {
				nf.Parent = uint32(parent + parentOffset)
				nf.Flags |= FieldFlagHasParent.Uint32()
				parentFields[parent] = struct{}{}
				checkParents[nf] = struct{}{}
			}
		}
		newFields = append(newFields, nf)
	}

	// Unref parent fields
	for p := range parentFields {
		FieldFlagUnreferenced.AddTo(&newFields[p].Flags)
	}

	// Check whether parent id is valid
	for f := range checkParents {
		parentID := f.Parent - uint32(parentOffset) // adjust offset again to match offset in newFields for this check
		if parentID >= uint32(len(newFields)) {
			return nil, fmt.Errorf("invalid parent for field %q", f.Name)
		}
	}

	var err error
	for i, f := range newFields {
		f.FullName, err = resolveNames(uint32(i), newFields, uint32(parentOffset))
		if err != nil {
			return nil, fmt.Errorf("resolving full fieldnames: %w", err)
		}
	}

	ds.fields = append(ds.fields, newFields...)

	for _, f := range newFields {
		ds.fieldMap[f.Name] = f
	}

	ds.payloadCount++

	return &fieldAccessor{ds: ds, f: &field{
		PayloadIndex: idx,
		Size:         size,
		Flags:        FieldFlagContainer.Uint32(),
	}}, nil
}

func (ds *dataSource) AddField(name string, opts ...FieldOption) (FieldAccessor, error) {
	ds.lock.Lock()
	defer ds.lock.Unlock()

	if _, ok := ds.fieldMap[name]; ok {
		return nil, fmt.Errorf("field %q already exists", name)
	}

	nf := &field{
		Name:     name,
		FullName: name,
		Index:    uint32(len(ds.fields)),
		Kind:     api.Kind_Invalid,
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
	ds.fieldMap[nf.FullName] = nf
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
				break
			}
		}
	}
	return res
}

func (ds *dataSource) Subscribe(fn DataFunc, priority int) {
	if fn == nil {
		return
	}

	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.subscriptionsSingle = append(ds.subscriptionsSingle, &subscription{
		priority: priority,
		fn:       fn,
	})
	sort.SliceStable(ds.subscriptionsSingle, func(i, j int) bool {
		return ds.subscriptionsSingle[i].priority < ds.subscriptionsSingle[j].priority
	})
}

func (ds *dataSource) SubscribeAny(fn DataFunc, priority int) {
	if fn == nil {
		return
	}

	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.subscriptionsElements = append(ds.subscriptionsElements, &subscription{
		priority: priority,
		fn:       fn,
	})
	sort.SliceStable(ds.subscriptionsElements, func(i, j int) bool {
		return ds.subscriptionsElements[i].priority < ds.subscriptionsElements[j].priority
	})

	ds.subscriptionsSingle = append(ds.subscriptionsSingle, &subscription{
		priority: priority,
		fn:       fn,
	})
	sort.SliceStable(ds.subscriptionsSingle, func(i, j int) bool {
		return ds.subscriptionsSingle[i].priority < ds.subscriptionsSingle[j].priority
	})
}

func (ds *dataSource) SubscribeArray(fn DataArrayFunc, priority int) {
	if fn == nil {
		return
	}

	ds.lock.Lock()
	defer ds.lock.Unlock()

	ds.subscriptionsArray = append(ds.subscriptionsArray, &subscriptionArray{
		priority: priority,
		fn:       fn,
	})
	sort.SliceStable(ds.subscriptionsArray, func(i, j int) bool {
		return ds.subscriptionsArray[i].priority < ds.subscriptionsArray[j].priority
	})
}

func (ds *dataSource) EmitAndRelease(d Packet) error {
	switch t := d.(type) {
	case *data:
		defer ds.dPool.Put(d)
		for _, sub := range ds.subscriptionsSingle {
			err := sub.fn(ds, t)
			if err != nil {
				return err
			}
		}
	case *dataArray:
		for _, sub := range ds.subscriptionsArray {
			err := sub.fn(ds, t)
			if err != nil {
				return err
			}
			if len(ds.subscriptionsElements) > 0 {
				for i := 0; i < t.Len(); i++ {
					for _, sub := range ds.subscriptionsElements {
						err := sub.fn(ds, t.Get(i))
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	return nil
}

func (ds *dataSource) Release(d Packet) {
	switch t := d.(type) {
	case *data:
		defer ds.dPool.Put(t)
	}
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

func (ds *dataSource) dumpEntry(wr io.Writer, payloads [][]byte) {
	for _, f := range ds.fields {
		if f.Offs+f.Size > uint32(len(payloads[f.PayloadIndex])) {
			fmt.Fprintf(wr, "%s (%d): ! invalid size\n", f.Name, f.Size)
			continue
		}
		fmt.Fprintf(wr, "%s (%d) [%s]: ", f.Name, f.Size, strings.Join(f.Tags, " "))
		if f.Offs > 0 || f.Size > 0 {
			fmt.Fprintf(wr, "%v\n", payloads[f.PayloadIndex][f.Offs:f.Offs+f.Size])
		} else {
			fmt.Fprintf(wr, "%v\n", payloads[f.PayloadIndex])
		}
	}
}

func (ds *dataSource) Dump(xd Packet, wr io.Writer) {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	switch nd := xd.(type) {
	case *data:
		ds.dumpEntry(wr, nd.Payloads)
	case *dataArray:
		for i := 0; i < nd.Len(); i++ {
			ds.dumpEntry(wr, nd.Elements[i].Payloads)
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

func (ds *dataSource) Accessors(rootOnly bool) []FieldAccessor {
	ds.lock.RLock()
	defer ds.lock.RUnlock()

	res := make([]FieldAccessor, 0, len(ds.fields))
	for _, f := range ds.fields {
		if rootOnly && FieldFlagHasParent.In(f.Flags) {
			continue
		}
		res = append(res, &fieldAccessor{
			ds: ds,
			f:  f,
		})
	}
	return res
}

func (ds *dataSource) IsRequested() bool {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return ds.requested
}

func (ds *dataSource) AddAnnotation(key, value string) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	ds.annotations[key] = value
}

func (ds *dataSource) AddTag(tag string) {
	ds.lock.Lock()
	defer ds.lock.Unlock()
	ds.tags = append(ds.tags, tag)
}

func (ds *dataSource) Annotations() map[string]string {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return maps.Clone(ds.annotations)
}

func (ds *dataSource) Tags() []string {
	ds.lock.RLock()
	defer ds.lock.RUnlock()
	return slices.Clone(ds.tags)
}
