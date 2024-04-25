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
	_ "embed"
	"sync"

	"github.com/Shopify/go-lua"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

//go:embed testlua.lua
var luatest string

type luaOperator struct{}

func (l *luaOperator) Name() string {
	return "lua"
}

func (l *luaOperator) Init(params *params.Params) error {
	return nil
}

func (l *luaOperator) GlobalParams() api.Params {
	return nil
}

func (l *luaOperator) InstanceParams() api.Params {
	return nil
}

func (l *luaOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	li := &luaOperatorInstance{
		gadgetCtx: gadgetCtx,
	}
	li.init()
	err := li.Init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	return li, nil
}

func (l *luaOperator) Priority() int {
	return 0
}

type luaOperatorInstance struct {
	lua       *lua.State
	gadgetCtx operators.GadgetContext
	lock      sync.Mutex
}

func (l *luaOperatorInstance) init() {
	ls := lua.NewState()
	l.lua = ls
	ls.Register("newTicker", l.newTicker)

	// Register type prototypes

	// GadgetContext
	l.lua.NewTable()
	l.lua.NewTable()
	l.lua.PushGoFunction(l.getDataSource)
	l.lua.SetField(-2, "GetDataSource")
	l.lua.PushGoFunction(l.addDataSource)
	l.lua.SetField(-2, "AddDataSource")
	l.lua.PushGoFunction(l.log)
	l.lua.SetField(-2, "Log")
	l.lua.SetField(-2, "__index")
	l.lua.SetGlobal("GadgetContext")

	// DataSource
	l.lua.NewTable()
	l.lua.NewTable()
	l.lua.PushGoFunction(l.dataSourceGetAccessor)
	l.lua.SetField(-2, "GetField")
	l.lua.PushGoFunction(l.dataSourceAddField)
	l.lua.SetField(-2, "AddField")
	l.lua.PushGoFunction(l.dataSourceSubscribe)
	l.lua.SetField(-2, "Subscribe")
	l.lua.PushGoFunction(l.dataSourceNewData)
	l.lua.SetField(-2, "NewData")
	l.lua.PushGoFunction(l.dataSourceEmitAndRelease)
	l.lua.SetField(-2, "EmitAndRelease")
	l.lua.PushGoFunction(l.dataSourceAddAnnotation)
	l.lua.SetField(-2, "AddAnnotation")
	l.lua.SetField(-2, "__index")
	l.lua.SetGlobal("DataSource")

	// FieldAccessor
	l.lua.NewTable()
	l.lua.NewTable()
	l.lua.PushGoFunction(l.fieldAccessorGetString)
	l.lua.SetField(-2, "GetString")
	l.lua.PushGoFunction(l.fieldAccessorSetString)
	l.lua.SetField(-2, "SetString")
	l.lua.PushGoFunction(l.fieldAccessorSetInt)
	l.lua.SetField(-2, "SetInt")
	l.lua.SetField(-2, "__index")
	l.lua.SetGlobal("FieldAccessor")

	lua.DoString(ls, luatest)
}

func (l *luaOperatorInstance) addDataSource(s *lua.State) int {
	dsName, ok := s.ToString(-1)
	if !ok {
		return 0
	}
	ds, err := l.gadgetCtx.RegisterDataSource(0, dsName)
	if err != nil {
		l.gadgetCtx.Logger().Warnf("could not register datasource: %v", err)
		return 0
	}
	l.lua.PushUserData(ds)

	l.lua.Global("DataSource")
	l.lua.SetMetaTable(-2)
	return 1
}

func (l *luaOperatorInstance) getDataSource(s *lua.State) int {
	dsName, ok := s.ToString(-1)
	if !ok {
		return 0
	}
	l.gadgetCtx.Logger().Debugf("ds name: %s", dsName)
	l.lua.PushUserData(l.gadgetCtx.GetDataSources()[dsName])

	l.lua.Global("DataSource")
	l.lua.SetMetaTable(-2)
	return 1
}

func (l *luaOperatorInstance) Name() string {
	return "lua"
}

func (l *luaOperatorInstance) Init(gadgetCtx operators.GadgetContext) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.lua.Global("init")
	l.lua.PushUserData(gadgetCtx)
	l.lua.Global("GadgetContext")
	l.lua.SetMetaTable(-2)
	return l.lua.ProtectedCall(1, 0, 0)
}

func (l *luaOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.lua.Global("preStart")
	l.lua.PushUserData(gadgetCtx)
	l.lua.Global("GadgetContext")
	l.lua.SetMetaTable(-2)
	return l.lua.ProtectedCall(1, 0, 0)
}

func (l *luaOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.lua.Global("start")
	l.lua.PushUserData(gadgetCtx)
	l.lua.Global("GadgetContext")
	l.lua.SetMetaTable(-2)
	return l.lua.ProtectedCall(1, 0, 0)
}

func (l *luaOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.lua.Global("stop")
	l.lua.PushUserData(gadgetCtx)
	l.lua.Global("GadgetContext")
	l.lua.SetMetaTable(-2)
	err := l.lua.ProtectedCall(1, 0, 0)
	l.lua = nil
	return err
}

func init() {
	operators.RegisterDataOperator(&luaOperator{})
}
