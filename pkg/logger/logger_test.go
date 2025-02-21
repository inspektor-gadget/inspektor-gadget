// Copyright 2025 The Inspektor Gadget authors
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

package logger

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockGenericLogger struct {
	level   Level
	lastMsg string
	lastLvl Level
}

func (m *mockGenericLogger) Log(severity Level, params ...any) {
	m.lastLvl = severity
	if len(params) > 0 {
		m.lastMsg = params[0].(string)
	}
}

func (m *mockGenericLogger) Logf(severity Level, format string, params ...any) {
	m.lastLvl = severity
	m.lastMsg = format
}

func (m *mockGenericLogger) SetLevel(l Level) { m.level = l }
func (m *mockGenericLogger) GetLevel() Level  { return m.level }

type mockDedicatedLogger struct {
	level   Level
	lastMsg string
	lastLvl Level
}

func (m *mockDedicatedLogger) Panic(params ...any) {
	m.lastLvl = PanicLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Panicf(format string, params ...any) {
	m.lastLvl = PanicLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) Fatal(params ...any) {
	m.lastLvl = FatalLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Fatalf(format string, params ...any) {
	m.lastLvl = FatalLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) Error(params ...any) {
	m.lastLvl = ErrorLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Errorf(format string, params ...any) {
	m.lastLvl = ErrorLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) Warn(params ...any) {
	m.lastLvl = WarnLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Warnf(format string, params ...any) {
	m.lastLvl = WarnLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) Info(params ...any) {
	m.lastLvl = InfoLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Infof(format string, params ...any) {
	m.lastLvl = InfoLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) Debug(params ...any) {
	m.lastLvl = DebugLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Debugf(format string, params ...any) {
	m.lastLvl = DebugLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) Trace(params ...any) {
	m.lastLvl = TraceLevel
	m.lastMsg = params[0].(string)
}

func (m *mockDedicatedLogger) Tracef(format string, params ...any) {
	m.lastLvl = TraceLevel
	m.lastMsg = format
}

func (m *mockDedicatedLogger) SetLevel(l Level) { m.level = l }
func (m *mockDedicatedLogger) GetLevel() Level  { return m.level }

func TestNewFromGenericLogger(t *testing.T) {
	mock := &mockGenericLogger{}
	logger := NewFromGenericLogger(mock)
	require.NotNil(t, logger, "logger should not be nil")

	tests := []struct {
		name     string
		logFunc  func()
		expected Level
		message  string
	}{
		{"Panic", func() { logger.Panic("panic-msg") }, PanicLevel, "panic-msg"},
		{"Panicf", func() { logger.Panicf("panicf-%s", "msg") }, PanicLevel, "panicf-%s"},
		{"Fatal", func() { logger.Fatal("fatal-msg") }, FatalLevel, "fatal-msg"},
		{"Fatalf", func() { logger.Fatalf("fatalf-%s", "msg") }, FatalLevel, "fatalf-%s"},
		{"Error", func() { logger.Error("error-msg") }, ErrorLevel, "error-msg"},
		{"Errorf", func() { logger.Errorf("errorf-%s", "msg") }, ErrorLevel, "errorf-%s"},
		{"Warn", func() { logger.Warn("warn-msg") }, WarnLevel, "warn-msg"},
		{"Warnf", func() { logger.Warnf("warnf-%s", "msg") }, WarnLevel, "warnf-%s"},
		{"Info", func() { logger.Info("info-msg") }, InfoLevel, "info-msg"},
		{"Infof", func() { logger.Infof("infof-%s", "msg") }, InfoLevel, "infof-%s"},
		{"Debug", func() { logger.Debug("debug-msg") }, DebugLevel, "debug-msg"},
		{"Debugf", func() { logger.Debugf("debugf-%s", "msg") }, DebugLevel, "debugf-%s"},
		{"Trace", func() { logger.Trace("trace-msg") }, TraceLevel, "trace-msg"},
		{"Tracef", func() { logger.Tracef("tracef-%s", "msg") }, TraceLevel, "tracef-%s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.logFunc()
			assert.Equal(t, tt.expected, mock.lastLvl, "logging level should match")
			assert.Contains(t, mock.lastMsg, tt.message, "log message should contain expected content")
		})
	}
}

func TestNewFromDedicatedLogger(t *testing.T) {
	mock := &mockDedicatedLogger{}
	logger := NewFromDedicatedLogger(mock)
	require.NotNil(t, logger, "logger should not be nil")

	levels := []struct {
		level   Level
		message string
		format  string
	}{
		{PanicLevel, "panic-msg", "panicf-%s"},
		{FatalLevel, "fatal-msg", "fatalf-%s"},
		{ErrorLevel, "error-msg", "errorf-%s"},
		{WarnLevel, "warn-msg", "warnf-%s"},
		{InfoLevel, "info-msg", "infof-%s"},
		{DebugLevel, "debug-msg", "debugf-%s"},
		{TraceLevel, "trace-msg", "tracef-%s"},
	}

	for _, lvl := range levels {
		t.Run(lvl.level.String(), func(t *testing.T) {
			logger.Log(lvl.level, lvl.message)
			assert.Equal(t, lvl.level, mock.lastLvl, "logging level should match for Log")
			assert.Contains(t, mock.lastMsg, lvl.message, "log message should contain expected content for Log")

			logger.Logf(lvl.level, lvl.format, "msg")
			assert.Equal(t, lvl.level, mock.lastLvl, "logging level should match for Logf")
			assert.Contains(t, mock.lastMsg, lvl.format, "log message should contain expected format for Logf")
		})
	}
}

func TestDefaultLogger(t *testing.T) {
	logger := DefaultLogger()
	assert.Same(t, log.StandardLogger(), logger, "default logger should be the standard logger")
}
