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
	"crypto/rand"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDataSourceDuplicatedField(t *testing.T) {
	ds := New(TypeEvent, "event")

	_, err := ds.AddField("foo")
	require.NoError(t, err)

	_, err = ds.AddField("foo")
	require.Error(t, err)
}

func TestDataSourceNonExistingField(t *testing.T) {
	ds := New(TypeEvent, "event")

	acc := ds.GetField("foo")
	require.Nil(t, acc)
}

func TestDataSourceEmptyField(t *testing.T) {
	ds := New(TypeEvent, "event")

	acc, err := ds.AddField("foo", WithFlags(FieldFlagEmpty))
	require.NoError(t, err)

	d := ds.NewData()

	err = acc.Set(d, []byte{0x01, 0x02, 0x03})
	require.Error(t, err)

	ret := acc.Get(d)
	require.Nil(t, ret)
}

func TestDataSourceAddFields(t *testing.T) {
	ds := New(TypeEvent, "event")

	// add some fields
	accessors := make([]FieldAccessor, 0)
	for i := 0; i < 10; i++ {
		acc, err := ds.AddField(fmt.Sprintf("foo-%d", i))
		require.NoError(t, err)
		accessors = append(accessors, acc)
	}

	d := ds.NewData()

	// check that writing and reading these fields is consistent
	for _, acc := range accessors {
		s, err := rand.Int(rand.Reader, big.NewInt(100))
		require.NoError(t, err)

		v := randBytes(int(s.Int64()))
		err = acc.Set(d, v)
		require.NoError(t, err)
		require.Equal(t, v, acc.Get(d))
	}
}

func TestDataSourceStaticFields(t *testing.T) {
	ds := New(TypeEvent, "event")

	fields := []Field{
		&dummyField{
			name:   "f1",
			size:   4,
			offset: 0,
		},
		&dummyField{
			name:   "f2",
			size:   4,
			offset: 4,
		},
		&dummyField{
			name:   "f3",
			size:   2,
			offset: 8,
		},
		&dummyField{
			name:   "f4",
			size:   1,
			offset: 10,
		},
		// 1-byte hole
		&dummyField{
			name:   "f5",
			size:   8,
			offset: 12,
		},
	}

	totalSize := uint32(4 + 4 + 2 + 1 + 8 + 1) // all sizes above + 1 byte for padding

	acc, err := ds.AddStaticFields(totalSize, fields)
	require.NoError(t, err)

	d := ds.NewData()

	// Try to read / write all fields at once
	val := randBytes(int(totalSize))
	acc.Set(d, val)
	require.Equal(t, val, acc.Get(d))

	for _, f := range fields {
		fDummy := f.(*dummyField)

		acc := ds.GetField(fDummy.name)
		require.NotNil(t, acc)

		// Check that the field is correctly read
		require.Equal(t, val[fDummy.offset:fDummy.offset+fDummy.size], acc.Get(d))

		// Check that the field is correctly written
		valf := randBytes(int(fDummy.size))
		err = acc.Set(d, valf)
		require.NoError(t, err)
		require.Equal(t, valf, acc.Get(d))
	}
}

// TODO: check fields + static on same tests

func TestDataSourceStaticFieldBadSize(t *testing.T) {
	ds := New(TypeEvent, "event")

	acc, err := ds.AddStaticFields(6, []Field{
		&dummyField{
			name:   "f1",
			size:   4,
			offset: 0,
		},
		&dummyField{
			name:   "f2",
			size:   2,
			offset: 4,
		},
	})
	require.NoError(t, err)

	d := ds.NewData()

	// Try to write full blob
	err = acc.Set(d, []byte{0x01, 0x02, 0x03})
	require.Error(t, err)

	// Try single field
	acc = ds.GetField("f1")
	err = acc.Set(d, []byte{0x01, 0x02, 0x03})
	require.Error(t, err)
}

func TestDataSourceStaticFieldsTooBig(t *testing.T) {
	ds := New(TypeEvent, "event")

	_, err := ds.AddStaticFields(2, []Field{
		&dummyField{
			name:   "f1",
			size:   4,
			offset: 0,
		},
		&dummyField{
			name:   "f2",
			size:   2,
			offset: 4,
		},
	})
	require.Error(t, err)
}

func TestDataSourceSubscribe(t *testing.T) {
	ds := New(TypeEvent, "event")

	// no-op
	ds.Subscribe(nil, 50)

	// ramdon list of priorities
	priorities := []int{30, 90, 54, 78, 71, 67, 90, 7, 92, 87}
	called := []int{}

	for _, priority := range priorities {
		priority := priority

		ds.Subscribe(func(fs DataSource, d Data) error {
			called = append(called, priority)
			return nil
		}, priority)
	}

	slices.Sort(priorities)

	d := ds.NewData()

	ds.EmitAndRelease(d)

	require.Equal(t, priorities, called)

}

type dummyField struct {
	name   string
	size   uint32
	offset uint32
}

func (d *dummyField) FieldName() string {
	return d.name
}

func (d *dummyField) FieldSize() uint32 {
	return d.size
}

func (d *dummyField) FieldOffset() uint32 {
	return d.offset
}

func randBytes(n int) []byte {
	ret := make([]byte, n)
	rand.Read(ret)
	return ret
}
