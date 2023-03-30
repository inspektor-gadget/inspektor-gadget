// Copyright 2023 The Inspektor Gadget authors
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

package gadgetservice

import (
	"fmt"

	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// Logger sends log messages through grpc
type Logger struct {
	send           func(*pb.GadgetEvent) error
	level          logger.Level
	fallbackLogger logger.Logger
}

func (l *Logger) SetLevel(level logger.Level) {
	l.level = level
}

func (l *Logger) GetLevel() logger.Level {
	return l.level
}

func (l *Logger) Logf(severity logger.Level, format string, params ...any) {
	if l.level < severity {
		return
	}
	ev := &pb.GadgetEvent{
		Type:    uint32(severity) << pb.EventLogShift,
		Payload: []byte(fmt.Sprintf(format, params...)),
	}
	if err := l.send(ev); err != nil {
		l.fallbackLogger.Logf(severity, format, params...)
	}
}

func (l *Logger) Log(severity logger.Level, params ...any) {
	if l.level < severity {
		return
	}
	ev := &pb.GadgetEvent{
		Type:    uint32(severity) << pb.EventLogShift,
		Payload: []byte(fmt.Sprintf("%+v", params...)),
	}
	if err := l.send(ev); err != nil {
		l.fallbackLogger.Log(severity, params...)
	}
}
