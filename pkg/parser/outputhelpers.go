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

package parser

import (
	"encoding/json"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// TextColumnsFormatter is the interface used for outputHelper
type TextColumnsFormatter interface {
	FormatHeader() string
	SetShowColumns([]string) error
	TransformEvent(string) (string, error)
	EventHandlerFunc() any
	EventHandlerFuncArray(...func()) any
	SetEventCallback(eventCallback func(string))
	SetEnableExtraLines(bool)
}

type ExtraLines interface {
	ExtraLines() []string
}

type ErrorGetter interface {
	GetType() types.EventType
	GetMessage() string
}

// outputHelpers hides all information about underlying types from the application
type outputHelper[T any] struct {
	parser *parser[T]
	*textcolumns.TextColumnsFormatter[T]
	eventCallback    func(string)
	enableExtraLines bool
}

func (oh *outputHelper[T]) forwardEvent(ev *T) {
	oh.eventCallback(oh.FormatEntry(ev))
	if !oh.enableExtraLines {
		return
	}
	// Output extra lines if the events support this
	for _, line := range any(ev).(ExtraLines).ExtraLines() {
		oh.eventCallback(line)
	}
}

func (oh *outputHelper[T]) EventHandlerFunc() any {
	if oh.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from TextColumnsFormatter")
	}
	return func(ev *T) {
		if getter, ok := any(ev).(ErrorGetter); ok {
			switch getter.GetType() {
			case types.ERR:
				oh.parser.writeLogMessage(logger.ErrorLevel, getter.GetMessage())
				return
			case types.WARN:
				oh.parser.writeLogMessage(logger.WarnLevel, getter.GetMessage())
				return
			case types.DEBUG:
				oh.parser.writeLogMessage(logger.DebugLevel, getter.GetMessage())
				return
			case types.INFO:
				oh.parser.writeLogMessage(logger.InfoLevel, getter.GetMessage())
				return
			}
		}

		oh.forwardEvent(ev)
	}
}

func (oh *outputHelper[T]) EventHandlerFuncArray(headerFuncs ...func()) any {
	if oh.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from TextColumnsFormatter")
	}
	return func(events []*T) {
		for _, hf := range headerFuncs {
			hf()
		}
		for _, ev := range events {
			oh.forwardEvent(ev)
		}
	}
}

func (oh *outputHelper[T]) SetEventCallback(eventCallback func(string)) {
	oh.eventCallback = eventCallback
}

// TransformEvent takes a JSON encoded line and transforms it to columns view
func (oh *outputHelper[T]) TransformEvent(line string) (string, error) {
	ev := new(T)
	err := json.Unmarshal([]byte(line), &ev)
	if err != nil {
		return "", err
	}

	// Apply filters
	if oh.parser.filterSpecs != nil && !oh.parser.filterSpecs.MatchAll(ev) {
		return "", nil
	}

	return oh.FormatEntry(ev), nil
}

func (oh *outputHelper[T]) SetShowColumns(cols []string) error {
	return oh.TextColumnsFormatter.SetShowColumns(cols)
}

func (oh *outputHelper[T]) SetEnableExtraLines(newVal bool) {
	// Check, whether the type actually supports extra lines
	if _, ok := any(new(T)).(ExtraLines); !ok {
		return
	}
	oh.enableExtraLines = newVal
}
