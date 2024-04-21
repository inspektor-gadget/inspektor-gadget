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
	"time"

	"github.com/Shopify/go-lua"
)

func (l *luaOperatorInstance) newTicker(s *lua.State) int {
	t, ok := s.ToInteger(-2)
	if !ok {
		l.gadgetCtx.Logger().Warnf("first parameter not an integer")
		return 0
	}
	str, ok := s.ToString(-1)
	if !ok {
		l.gadgetCtx.Logger().Warnf("second parameter not a string")
		return 0
	}
	ticker := time.NewTicker(time.Duration(t) * time.Millisecond)
	go func() {
		for {
			select {
			case <-l.gadgetCtx.Context().Done():
				return
			case <-ticker.C:
				l.lock.Lock()
				l.lua.Global(str)
				err := l.lua.ProtectedCall(0, 0, 0)
				l.lock.Unlock()
				if err != nil {
					l.gadgetCtx.Logger().Warnf("failed to run ticker: %v", err)
				}
			}
		}
	}()
	return 0
}

func (l *luaOperatorInstance) log(s *lua.State) int {
	str, ok := s.ToString(-1)
	if !ok {
		l.gadgetCtx.Logger().Warnf("got not printable string from lua")
		return 0
	}
	l.gadgetCtx.Logger().Debug(str)
	return 0
}
