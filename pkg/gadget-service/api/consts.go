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

package api

const (
	VersionGadgetInfo        = 1
	VersionGadgetRunProtocol = 1
)

const (
	EventTypeGadgetPayload uint32 = 0
	EventTypeGadgetResult  uint32 = 1
	EventTypeGadgetDone    uint32 = 2
	EventTypeGadgetJobID   uint32 = 3

	// EventTypeGadgetInfo is transmitted after a gadget has been initialized; while GetGadgetInfo() can return
	// cached data, this payload will always be up-to-date and reflect the actual layout of the data that is
	// expected / sent.
	EventTypeGadgetInfo uint32 = 4

	EventLogShift = 16
)

const (
	KindFlagArray Kind = 0x10000000
)

func ArrayOf(kind Kind) Kind {
	return kind | KindFlagArray
}

func IsArrayKind(kind Kind) bool {
	return kind&KindFlagArray != 0
}

const (
	GadgetServicePort = 8080
	DefaultDaemonPath = "unix:///var/run/ig/ig.socket"
)

const (
	DataSourceFlagsBigEndian uint32 = 1 << iota
)

const (
	TypeUnknown     = ""
	TypeBool        = "bool"
	TypeString      = "string"
	TypeBytes       = "bytes"
	TypeInt         = "int"
	TypeInt8        = "int8"
	TypeInt16       = "int16"
	TypeInt32       = "int32"
	TypeInt64       = "int64"
	TypeUint        = "uint"
	TypeUint8       = "uint8"
	TypeUint16      = "uint16"
	TypeUint32      = "uint32"
	TypeUint64      = "uint64"
	TypeFloat32     = "float32"
	TypeFloat64     = "float64"
	TypeDuration    = "duration"
	TypeIP          = "ip"
	TypeStringSlice = "[]string"
)

const (
	// TagSrcEbpf defines that a field was extracted from eBPF
	TagSrcEbpf = "src:ebpf"
)

const (
	FetchCountAnnotation    = "fetch-count"
	FetchIntervalAnnotation = "fetch-interval"
)

const (
	// GadgetInfoRequestFlagUseInstance defines that the service should get gadget information from an existing gadget
	// instance; in this case the imageName of the GadgetInfoRequest is evaluated as the ID of the gadget instance
	GadgetInfoRequestFlagUseInstance = 1 << iota
)
