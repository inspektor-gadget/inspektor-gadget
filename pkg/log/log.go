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

package log

import (
	"io"
	"log/slog"

	"github.com/sirupsen/logrus"
)

type SlogHook struct {
	logger *slog.Logger
}

func (h *SlogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *SlogHook) Fire(entry *logrus.Entry) error {
	level := mapLogrusLevel(entry.Level)

	attrs := make([]slog.Attr, 0, len(entry.Data))
	for k, v := range entry.Data {
		attrs = append(attrs, slog.Any(k, v))
	}

	// Preserve timestamp and caller info if desired
	h.logger.LogAttrs(entry.Context, level, entry.Message, attrs...)
	return nil
}

func mapLogrusLevel(level logrus.Level) slog.Level {
	switch level {
	case logrus.TraceLevel:
		return slog.LevelDebug - 1
	case logrus.DebugLevel:
		return slog.LevelDebug
	case logrus.InfoLevel:
		return slog.LevelInfo
	case logrus.WarnLevel:
		return slog.LevelWarn
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func SetupLogrusWrapper(logger *slog.Logger) {
	logrus.AddHook(&SlogHook{logger: logger})
	logrus.SetOutput(io.Discard)
}
