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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
)

// TextColumnsFormatter is the interface used for outputHelper
type TextColumnsFormatter interface {
	FormatHeader() string
	SetShowColumns([]string) error
	EventHandlerFunc() any
	EventHandlerFuncArray(...func()) any
	SetEventCallback(eventCallback func(string))
}

// outputHelpers hides all information about underlying types from the application
type outputHelper[T any] struct {
	*textcolumns.TextColumnsFormatter[T]
	eventCallback func(string)
}

func (oh *outputHelper[T]) forwardEvent(ev *T) {
	oh.eventCallback(oh.FormatEntry(ev))
}

func (oh *outputHelper[T]) EventHandlerFunc() any {
	if oh.eventCallback == nil {
		panic("set event callback before getting the EventHandlerFunc from TextColumnsFormatter")
	}
	return func(ev *T) {
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

func (oh *outputHelper[T]) SetShowColumns(cols []string) error {
	return oh.TextColumnsFormatter.SetShowColumns(cols)
}
