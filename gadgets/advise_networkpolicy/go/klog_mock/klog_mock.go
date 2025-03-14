package klog

// Mock implementation of klog for testing purposes. Thank you Copilot

import (
	"context"
	"io"
)

// Logger represents a structured logger interface
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(err error, msg string, keysAndValues ...interface{})
	WithCallDepth(depth int) Logger
	WithName(name string) Logger
}

// Info logs to the INFO log.
func Info(args ...interface{}) {}

// Infoln logs to the INFO log.
func Infoln(args ...interface{}) {}

// Infof logs to the INFO log with formatting.
func Infof(format string, args ...interface{}) {}

// InfoS logs to the INFO log with structured data.
func InfoS(msg string, keysAndValues ...interface{}) {}

// Warning logs to the WARNING log.
func Warning(args ...interface{}) {}

// Warningln logs to the WARNING log.
func Warningln(args ...interface{}) {}

// Warningf logs to the WARNING log with formatting.
func Warningf(format string, args ...interface{}) {}

// Error logs to the ERROR log.
func Error(args ...interface{}) {}

// Errorln logs to the ERROR log.
func Errorln(args ...interface{}) {}

// Errorf logs to the ERROR log with formatting.
func Errorf(format string, args ...interface{}) {}

// ErrorS logs to the ERROR log with structured data.
func ErrorS(err error, msg string, keysAndValues ...interface{}) {}

// Fatal logs to the FATAL log.
func Fatal(args ...interface{}) {}

// Fatalln logs to the FATAL log.
func Fatalln(args ...interface{}) {}

// Fatalf logs to the FATAL log with formatting.
func Fatalf(format string, args ...interface{}) {}

// V returns a leveled logger.
func V(level int) Verbose {
	return Verbose(true)
}

// Verbose is a leveled logger used for verbose logging.
type Verbose bool

// Info logs to the INFO log if the level is enabled.
func (v Verbose) Info(args ...interface{}) {}

// Infoln logs to the INFO log if the level is enabled.
func (v Verbose) Infoln(args ...interface{}) {}

// Infof logs to the INFO log with formatting if the level is enabled.
func (v Verbose) Infof(format string, args ...interface{}) {}

// Enabled returns true if this log level is enabled.
func (v Verbose) Enabled() bool {
	return bool(v)
}

// KObj returns a textual representation of a Kubernetes object.
func KObj(obj interface{}) string {
	return ""
}

// FromContext extracts a logger from context
func FromContext(ctx context.Context) Logger {
	return mockLogger{}
}

// LoggerWithName returns a logger with a name
// Support two forms of call:
// 1. LoggerWithName(name string) - the standard call
// 2. LoggerWithName(logger Logger, name string) - called from k8s.io/apimachinery
func LoggerWithName(loggerOrName interface{}, name ...string) Logger {
	return mockLogger{}
}

// LoggerWithValues is another method to create a logger with values
func LoggerWithValues(keysAndValues ...interface{}) Logger {
	return mockLogger{}
}

// mockLogger is a basic implementation of Logger interface
type mockLogger struct{}

func (l mockLogger) Info(msg string, keysAndValues ...interface{})             {}
func (l mockLogger) Error(err error, msg string, keysAndValues ...interface{}) {}
func (l mockLogger) WithCallDepth(depth int) Logger                            { return l }
func (l mockLogger) WithName(name string) Logger                               { return l }

// FlushLogger flushes all pending log I/O.
func FlushLogger() {}

// SetOutput sets the output destination for logs.
func SetOutput(w io.Writer) {}
