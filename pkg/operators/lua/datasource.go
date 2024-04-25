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

func (l *luaOperatorInstance) dataSourceNewData(s *lua.State) int {
	ds, ok := s.ToUserData(-1).(datasource.DataSource)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not a datasource: %T", s.ToUserData(-1))
		return 0
	}
	data := ds.NewData()
	s.PushUserData(data)
	return 1
}

func (l *luaOperatorInstance) dataSourceAddAnnotation(s *lua.State) int {
	ds, ok := s.ToUserData(-3).(datasource.DataSource)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not a datasource: %T", s.ToUserData(-1))
		return 0
	}
	key, _ := s.ToString(-2) // TODO
	val, _ := s.ToString(-1) // TODO
	ds.AddAnnotation(key, val)
	return 0
}

func (l *luaOperatorInstance) dataSourceEmitAndRelease(s *lua.State) int {
	ds, ok := s.ToUserData(-2).(datasource.DataSource)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not a datasource: %T", s.ToUserData(-2))
		return 0
	}
	data, ok := s.ToUserData(-1).(datasource.Data)
	if !ok {
		l.gadgetCtx.Logger().Warnf("second parameter not data: %T", s.ToUserData(-1))
		return 0
	}
	ds.EmitAndRelease(data)
	return 0
}

func (l *luaOperatorInstance) dataSourceSubscribe(s *lua.State) int {
	ds, ok := s.ToUserData(-2).(datasource.DataSource)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not a datasource: %T", s.ToUserData(-2))
		return 0
	}
	fnName, ok := s.ToString(-1)
	if !ok {
		l.gadgetCtx.Logger().Warnf("second parameter not a string")
		return 0
	}
	ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
		l.lock.Lock()
		s.Global(fnName)
		s.PushUserData(source)
		s.PushUserData(data)
		err := s.ProtectedCall(2, 0, 0)
		l.lock.Unlock()
		if err != nil {
			l.gadgetCtx.Logger().Warnf("failed to call event: %v", err)
		}
		return nil
	}, 0)
	return 1
}

func (l *luaOperatorInstance) dataSourceGetAccessor(s *lua.State) int {
	ds, ok := s.ToUserData(-2).(datasource.DataSource)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not a datasource: %T", s.ToUserData(-2))
		return 0
	}
	fieldName, ok := s.ToString(-1)
	if !ok {
		return 0
	}
	s.PushUserData(ds.GetField(fieldName))
	l.lua.Global("FieldAccessor")
	l.lua.SetMetaTable(-2)
	return 1
}

func (l *luaOperatorInstance) dataSourceAddField(s *lua.State) int {
	ds, ok := s.ToUserData(-3).(datasource.DataSource)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not a datasource: %T", s.ToUserData(-2))
		return 0
	}
	fieldName, ok := s.ToString(-2)
	if !ok {
		return 0
	}

	fType, _ := s.ToInteger(-1)

	acc, err := ds.AddField(fieldName, datasource.WithKind(api.Kind(fType)))
	if err != nil {
		l.gadgetCtx.Logger().Warnf("could not add field: %v", err)
		return 0
	}

	l.gadgetCtx.Logger().Debugf("field %q added from lua", fieldName)
	s.PushUserData(acc)
	l.lua.Global("FieldAccessor")
	l.lua.SetMetaTable(-2)
	return 1
}
