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

package lua

import (
	"github.com/Shopify/go-lua"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (l *luaOperatorInstance) fieldAccessorGetString(s *lua.State) int {
	acc, ok := s.ToUserData(-2).(datasource.FieldAccessor)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not an accessor: %T", s.ToUserData(1))
		return 0
	}
	data, ok := s.ToUserData(-1).(datasource.Data)
	if !ok {
		l.gadgetCtx.Logger().Warnf("second parameter not data: %T", s.ToUserData(2))
		return 0
	}
	s.PushString(acc.String(data))
	return 1
}

func (l *luaOperatorInstance) fieldAccessorSetString(s *lua.State) int {
	acc, ok := s.ToUserData(-3).(datasource.FieldAccessor)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not an accessor: %T", s.ToUserData(1))
		return 0
	}
	data, ok := s.ToUserData(-2).(datasource.Data)
	if !ok {
		l.gadgetCtx.Logger().Warnf("second parameter not data: %T", s.ToUserData(2))
		return 0
	}
	strval, ok := s.ToString(-1)
	if !ok {
		l.gadgetCtx.Logger().Warn("third parameter not string")
		return 0
	}
	acc.Set(data, []byte(strval))
	return 0
}

func (l *luaOperatorInstance) fieldAccessorSetInt(s *lua.State) int {
	acc, ok := s.ToUserData(-3).(datasource.FieldAccessor)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not an accessor: %T", s.ToUserData(1))
		return 0
	}
	data, ok := s.ToUserData(-2).(datasource.Data)
	if !ok {
		l.gadgetCtx.Logger().Warnf("second parameter not data: %T", s.ToUserData(2))
		return 0
	}
	val, ok := s.ToInteger(-1)
	if !ok {
		l.gadgetCtx.Logger().Warn("third parameter not int")
		return 0
	}
	switch acc.Type() {
	case api.Kind_Int8:
		acc.Set(data, []byte{byte(int8(val))})
	case api.Kind_Int16:
		d := make([]byte, 2)
		acc.Set(data, d)
		acc.PutInt16(data, int16(val))
	case api.Kind_Int32:
		d := make([]byte, 4)
		acc.Set(data, d)
		acc.PutInt32(data, int32(val))
	case api.Kind_Int64:
		d := make([]byte, 8)
		acc.Set(data, d)
		acc.PutInt64(data, int64(val))
	case api.Kind_Uint8:
		acc.Set(data, []byte{byte(val)})
	case api.Kind_Uint16:
		d := make([]byte, 2)
		acc.Set(data, d)
		acc.PutUint16(data, uint16(val))
	case api.Kind_Uint32:
		d := make([]byte, 4)
		acc.Set(data, d)
		acc.PutUint32(data, uint32(val))
	case api.Kind_Uint64:
		d := make([]byte, 8)
		acc.Set(data, d)
		acc.PutUint64(data, uint64(val))
	}
	return 0
}
