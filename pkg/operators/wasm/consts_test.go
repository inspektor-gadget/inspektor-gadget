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

package wasm

import (
	"testing"
	_ "unsafe"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	wasmapi "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// take internal consts from wasmapi

//go:linkname wasmapiSubscriptionTypeData github.com/inspektor-gadget/inspektor-gadget/wasmapi/go.subscriptionTypeDataVar
var wasmapiSubscriptionTypeData uint32

//go:linkname wasmapiSubscriptionTypeArray github.com/inspektor-gadget/inspektor-gadget/wasmapi/go.subscriptionTypeArrayVar
var wasmapiSubscriptionTypeArray uint32

//go:linkname wasmapiSubscriptionTypePacket github.com/inspektor-gadget/inspektor-gadget/wasmapi/go.subscriptionTypePacketVar
var wasmapiSubscriptionTypePacket uint32

// TestConsts tests that the consts defined here and in the api are in sync
func TestConsts(t *testing.T) {
	t.Parallel()

	// logLevel
	assert.EqualValues(t, wasmapi.ErrorLevel, errorLevel)
	assert.EqualValues(t, wasmapi.WarnLevel, warnLevel)
	assert.EqualValues(t, wasmapi.InfoLevel, infoLevel)
	assert.EqualValues(t, wasmapi.DebugLevel, debugLevel)
	assert.EqualValues(t, wasmapi.TraceLevel, traceLevel)

	// FieldKind
	assert.EqualValues(t, wasmapi.Kind_Invalid, api.Kind_Invalid)
	assert.EqualValues(t, wasmapi.Kind_Bool, api.Kind_Bool)
	assert.EqualValues(t, wasmapi.Kind_Int8, api.Kind_Int8)
	assert.EqualValues(t, wasmapi.Kind_Int16, api.Kind_Int16)
	assert.EqualValues(t, wasmapi.Kind_Int32, api.Kind_Int32)
	assert.EqualValues(t, wasmapi.Kind_Int64, api.Kind_Int64)
	assert.EqualValues(t, wasmapi.Kind_Uint8, api.Kind_Uint8)
	assert.EqualValues(t, wasmapi.Kind_Uint16, api.Kind_Uint16)
	assert.EqualValues(t, wasmapi.Kind_Uint32, api.Kind_Uint32)
	assert.EqualValues(t, wasmapi.Kind_Uint64, api.Kind_Uint64)
	assert.EqualValues(t, wasmapi.Kind_Float32, api.Kind_Float32)
	assert.EqualValues(t, wasmapi.Kind_Float64, api.Kind_Float64)
	assert.EqualValues(t, wasmapi.Kind_String, api.Kind_String)
	assert.EqualValues(t, wasmapi.Kind_CString, api.Kind_CString)
	assert.EqualValues(t, wasmapi.Kind_Bytes, api.Kind_Bytes)

	// DataSourceType
	assert.EqualValues(t, wasmapi.DataSourceTypeUndefined, datasource.TypeUndefined)
	assert.EqualValues(t, wasmapi.DataSourceTypeSingle, datasource.TypeSingle)
	assert.EqualValues(t, wasmapi.DataSourceTypeArray, datasource.TypeArray)

	// subscriptionType
	assert.EqualValues(t, wasmapiSubscriptionTypeData, subscriptionTypeData)
	assert.EqualValues(t, wasmapiSubscriptionTypeArray, subscriptionTypeArray)
	assert.EqualValues(t, wasmapiSubscriptionTypePacket, subscriptionTypePacket)
}
