// Copyright 2023-2024 The Inspektor Gadget authors
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
	"io"

	"github.com/spf13/viper"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type Type uint32

const (
	TypeUndefined Type = iota
	TypeSingle
	TypeArray
)

type dsError string

func (err dsError) Error() string {
	return string(err)
}

const (
	// ErrDiscard can be returned on subscription callbacks to tell the datasource to discard the entity (packet, array
	// or single event, depending on the subscription)
	ErrDiscard = dsError("discarded")
)

type Data interface {
	private()
	payload() [][]byte
}

type DataArray interface {
	// New returns a newly allocated data element. Use Append to add it to the array
	New() Data

	// Append appends Data to the array
	Append(Data)

	// Release releases the memory of Data; Data may not be used after calling this
	Release(Data)

	// Len returns the number of elements in the array
	Len() int

	// Get returns the element at the given index
	Get(int) Data

	// Swap swaps two elements of the array by their index
	Swap(i, j int)
}

type Packet interface {
	// SetSeq sets the sequence number of the packet
	SetSeq(uint32)

	// Raw returns the raw proto message for marshaling and unmarshaling
	Raw() proto.Message
}

type PacketSingle interface {
	Packet
	Data
}

type PacketArray interface {
	Packet
	DataArray
}

// DataFunc is the callback that will be called for Data emitted by a DataSource. Data has to be consumed
// synchronously and may not be accessed after returning - make a copy if you need to hold on to Data.
type DataFunc func(DataSource, Data) error

// ArrayFunc is analogous to DataFunc, but for DataArray
type ArrayFunc func(DataSource, DataArray) error

// PacketFunc is analogous to DataFunc, but for Packet
type PacketFunc func(DataSource, Packet) error

// DataSource is an interface that represents a data source of a gadget. Usually, it represents a map in eBPF and some
// tooling around handling it in Go. An eBPF program can have multiple DataSources, each one representing a different
// map.
type DataSource interface {
	// Name returns the name of the data source
	Name() string

	// Type returns the type of the data source
	Type() Type

	// AddStaticFields adds fields inside a container that has a fixed size; use it to directly map for example
	// eBPF structs
	AddStaticFields(totalSize uint32, fields []StaticField) (FieldAccessor, error)

	// AddField adds a field as a new payload
	AddField(fieldName string, kind api.Kind, options ...FieldOption) (FieldAccessor, error)

	// NewPacketSingle builds a new PacketSingle that can be written to
	NewPacketSingle() (PacketSingle, error)
	// NewPacketSingleFromRaw builds a new PacketSingle from a raw bytes slice coming from protobuf
	NewPacketSingleFromRaw(b []byte) (PacketSingle, error)

	// NewPacketArray and NewPacketArrayFromRaw are analogous to NewPacketSingle and NewPacketSingleFromRaw, but for
	// PacketArray
	NewPacketArray() (PacketArray, error)
	NewPacketArrayFromRaw(b []byte) (PacketArray, error)

	GetField(fieldName string) FieldAccessor
	GetFieldsWithTag(tag ...string) []FieldAccessor

	// EmitAndRelease sends Packet through the operator chain and releases it afterward;
	// Packet may not be used after calling this. This should only be used in the running phase of the gadget, not
	// in the initialization phase.
	EmitAndRelease(Packet) error

	// Release releases the memory of Packet; Packet may not be used after calling this
	Release(Packet)

	// ReportLostData reports a number of lost data cases
	ReportLostData(lostSampleCount uint64)

	// Dump dumps the content of Packet to a writer for debugging purposes
	Dump(Packet, io.Writer)

	// Subscribe makes sure that events emitted from this DataSource are passed to DataFunc; subscribers will be
	// sorted by priority and handed over data in that order (lower numbers = earlier). Subscriptions to
	// DataSources should only happen in the initialization phase. Data sent to dataFn has to be consumed synchronously
	// and must not be accessed after returning. If the data source type is TypeArray, the dataFn will be called for each
	// data element in the array. For TypeSingle, it will be called once. If you want to receive the entire Packet
	// (PacketSingle, PacketArray, etc), use SubscribePacket instead.
	Subscribe(dataFn DataFunc, priority int) error

	// SubscribeArray works like Subscribe, but it will receive the entire DataArray instead of the data elements in it.
	// Notice that if you subscribe to both Subscribe and SubscribeArray, the same data elements will be sent to DataFunc
	// and also to ArrayFunc (along with the other elements in the array).
	SubscribeArray(dataFn ArrayFunc, priority int) error

	// SubscribePacket works like Subscribe, but it will receive the entire Packet instead of the data elements in it.
	// It means that PacketFunc could be called with PacketSingle, PacketArray or any other type implementing Packet.
	// Subscriptions can know the type of the packet by checking the data source type: TypeSingle, TypeArray, etc.
	SubscribePacket(packetFn PacketFunc, priority int) error

	Parser() (parser.Parser, error)

	Fields() []*api.Field

	Accessors(rootOnly bool) []FieldAccessor

	SetRequested(bool)
	IsRequested() bool

	// ByteOrder returns a binary accessor using the byte order of the creator of the DataSource
	ByteOrder() binary.ByteOrder

	AddAnnotation(key, value string)
	AddTag(tag string)

	Annotations() map[string]string
	Tags() []string

	CopyFieldsTo(DataSource) error
}

type DataSourceOption func(*dataSource)

func WithConfig(v *viper.Viper) DataSourceOption {
	return func(source *dataSource) {
		source.config = v
	}
}
