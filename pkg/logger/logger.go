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

type DedicatedLogger interface {
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
}

type GenericLogger interface {
	Log(severity Level, params ...any)
	Logf(severity Level, format string, params ...any)
}

type GenericLoggerWithLevelSetter interface {
	GenericLogger
	LevelGetterSetter
}

type DedicatedLoggerWithLevelSetter interface {
	DedicatedLogger
	LevelGetterSetter
}

type LevelGetterSetter interface {
	SetLevel(Level)
	GetLevel() Level
}

type Logger interface {
	DedicatedLogger
	GenericLogger
	LevelGetterSetter
}

func NewFromGenericLogger(logger GenericLoggerWithLevelSetter) Logger {
	return &StandardDedicatedLogger{GenericLoggerWithLevelSetter: logger}
}

func NewFromDedicatedLogger(logger DedicatedLoggerWithLevelSetter) Logger {
	return &StandardGenericLogger{DedicatedLoggerWithLevelSetter: logger}
}

type StandardDedicatedLogger struct {
	GenericLoggerWithLevelSetter
}

func (s *StandardDedicatedLogger) Panic(params ...any) {
	s.Log(PanicLevel, params...)
}

func (s *StandardDedicatedLogger) Panicf(fmt string, params ...any) {
	s.Logf(PanicLevel, fmt, params...)
}

func (s *StandardDedicatedLogger) Fatal(params ...any) {
	s.Log(FatalLevel, params...)
}

func (s *StandardDedicatedLogger) Fatalf(fmt string, params ...any) {
	s.Logf(FatalLevel, fmt, params...)
}

func (s *StandardDedicatedLogger) Error(params ...any) {
	s.Log(ErrorLevel, params...)
}

func (s *StandardDedicatedLogger) Errorf(fmt string, params ...any) {
	s.Logf(ErrorLevel, fmt, params...)
}

func (s *StandardDedicatedLogger) Warn(params ...any) {
	s.Log(WarnLevel, params...)
}

func (s *StandardDedicatedLogger) Warnf(fmt string, params ...any) {
	s.Logf(WarnLevel, fmt, params...)
}

func (s *StandardDedicatedLogger) Info(params ...any) {
	s.Log(InfoLevel, params...)
}

func (s *StandardDedicatedLogger) Infof(fmt string, params ...any) {
	s.Logf(InfoLevel, fmt, params...)
}

func (s *StandardDedicatedLogger) Debug(params ...any) {
	s.Log(DebugLevel, params...)
}

func (s *StandardDedicatedLogger) Debugf(fmt string, params ...any) {
	s.Logf(DebugLevel, fmt, params...)
}

func (s *StandardDedicatedLogger) Trace(params ...any) {
	s.Log(TraceLevel, params...)
}

func (s *StandardDedicatedLogger) Tracef(fmt string, params ...any) {
	s.Logf(TraceLevel, fmt, params...)
}

type StandardGenericLogger struct {
	DedicatedLoggerWithLevelSetter
}

func (s *StandardGenericLogger) Log(severity Level, params ...any) {
	switch severity {
	case PanicLevel:
		s.Panic(params...)
	case FatalLevel:
		s.Fatal(params...)
	case ErrorLevel:
		s.Error(params...)
	case WarnLevel:
		s.Warn(params...)
	case InfoLevel:
		s.Info(params...)
	case DebugLevel:
		s.Debug(params...)
	case TraceLevel:
		s.Trace(params...)
	}
}

func (s *StandardGenericLogger) Logf(severity Level, format string, params ...any) {
	switch severity {
	case PanicLevel:
		s.Panicf(format, params...)
	case FatalLevel:
		s.Fatalf(format, params...)
	case ErrorLevel:
		s.Errorf(format, params...)
	case WarnLevel:
		s.Warnf(format, params...)
	case InfoLevel:
		s.Infof(format, params...)
	case DebugLevel:
		s.Debugf(format, params...)
	case TraceLevel:
		s.Tracef(format, params...)
	}
}

func DefaultLogger() Logger {
	return log.StandardLogger()
}
