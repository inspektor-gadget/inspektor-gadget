// Copyright 2022-2023 The Inspektor Gadget authors
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

/*
Package logger provides a logger interface that is available to gadgets
and runtimes.
*/
package logger

import log "github.com/sirupsen/logrus"

type Level = log.Level

// we use the log levels from logrus here
const (
	PanicLevel = log.PanicLevel
	FatalLevel = log.FatalLevel
	ErrorLevel = log.ErrorLevel
	WarnLevel  = log.WarnLevel
	InfoLevel  = log.InfoLevel
	DebugLevel = log.DebugLevel
	TraceLevel = log.TraceLevel
)

type Logger interface {
	Panic(params ...any)
	Panicf(fmt string, params ...any)
	Fatal(params ...any)
	Fatalf(fmt string, params ...any)
	Error(params ...any)
	Errorf(fmt string, params ...any)
	Warn(params ...any)
	Warnf(fmt string, params ...any)
	Info(params ...any)
	Infof(fmt string, params ...any)
	Debug(params ...any)
	Debugf(fmt string, params ...any)
	Trace(params ...any)
	Tracef(fmt string, params ...any)
	SetLevel(Level)
}

func DefaultLogger() Logger {
	return log.StandardLogger()
}
