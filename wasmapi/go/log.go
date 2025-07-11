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

package api

import (
	"fmt"
	"runtime"
	_ "unsafe"
)

//go:wasmimport ig gadgetLog
//go:linkname gadgetLog gadgetLog
func gadgetLog(level uint32, str uint64)

//go:wasmimport ig gadgetShouldLog
//go:linkname gadgetShouldLog gadgetShouldLog
func gadgetShouldLog(level uint32) uint32

type logLevel uint32

const (
	ErrorLevel logLevel = iota
	WarnLevel
	InfoLevel
	DebugLevel
	TraceLevel
)

func log(level logLevel, message string) {
	gadgetLog(uint32(level), uint64(stringToBufPtr(message)))
	runtime.KeepAlive(message)
}

func Log(level logLevel, args ...any) {
	if gadgetShouldLog(uint32(level)) == 1 {
		log(level, fmt.Sprint(args...))
	}
}

func Logf(level logLevel, format string, args ...any) {
	if gadgetShouldLog(uint32(level)) == 1 {
		log(level, fmt.Sprintf(format, args...))
	}
}

func Error(params ...any) {
	Log(ErrorLevel, params...)
}

func Errorf(fmt string, params ...any) {
	Logf(ErrorLevel, fmt, params...)
}

func Warn(params ...any) {
	Log(WarnLevel, params...)
}

func Warnf(fmt string, params ...any) {
	Logf(WarnLevel, fmt, params...)
}

func Info(params ...any) {
	Log(InfoLevel, params...)
}

func Infof(fmt string, params ...any) {
	Logf(InfoLevel, fmt, params...)
}

func Debug(params ...any) {
	Log(DebugLevel, params...)
}

func Debugf(fmt string, params ...any) {
	Logf(DebugLevel, fmt, params...)
}

func Trace(params ...any) {
	Log(TraceLevel, params...)
}

func Tracef(fmt string, params ...any) {
	Logf(TraceLevel, fmt, params...)
}
