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
	"context"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// Log levels for gadgetLog
// Keep in sync with pkg/apis/wasm/log.go
const (
	errorLevel uint32 = iota
	warnLevel
	infoLevel
	debugLevel
	traceLevel
)

func (i *wasmOperatorInstance) addLogFuncs(env wazero.HostModuleBuilder) {
	logFn := func(ctx context.Context, m wapi.Module, stack []uint64) {
		logLevel := wapi.DecodeU32(stack[0])
		msgPtr := stack[1]

		str, err := stringFromStack(m, msgPtr)
		if err != nil {
			i.logger.Warnf("gadgetlog: reading string from stack: %v", err)
			return
		}

		switch logLevel {
		case errorLevel:
			i.logger.Error(str)
		case warnLevel:
			i.logger.Warn(str)
		case infoLevel:
			i.logger.Info(str)
		case debugLevel:
			i.logger.Debug(str)
		case traceLevel:
			i.logger.Trace(str)
		default:
			i.logger.Warnf("gadgetlog: gadget used unknown log level: %d for %s", logLevel, str)
		}
	}

	shouldLogFn := func(ctx context.Context, m wapi.Module, stack []uint64) {
		logLevel := wapi.DecodeU32(stack[0])
		loggerLevel := i.logger.GetLevel()

		// Logger defines [PanicLevel, TraceLevel] but WASM API only defines
		// [ErrorLevel, TraceLevel].
		// If logger level is below ErrorLevel, we should not log.
		// Otherwise log if the level are enabled by shifting WASM API log level.
		if loggerLevel >= logger.ErrorLevel && uint32(loggerLevel) >= logLevel+uint32(logger.ErrorLevel) {
			stack[0] = 1
		} else {
			stack[0] = 0
		}
	}

	exportFunction(env, "gadgetLog", logFn,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // log level
			wapi.ValueTypeI64, // message
		},
		[]wapi.ValueType{},
	)
	exportFunction(env, "gadgetShouldLog", shouldLogFn,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // log level
		},
		[]wapi.ValueType{
			wapi.ValueTypeI32, // bool
		},
	)
}
