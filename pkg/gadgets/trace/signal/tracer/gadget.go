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

package tracer

import (
	"errors"
	"strconv"
	"strings"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "signal"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryTrace
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Trace signals received by processes"
}

const (
	ParamPID          = "pid"
	ParamTargetSignal = "signal"
	ParamFailedOnly   = "failed-only"
	ParamKillOnly     = "kill-only"
)

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamPID,
			DefaultValue: "0",
			Description:  "Show only signal sent by this particular PID",
			TypeHint:     params.TypeInt32,
		},
		{
			Key:         ParamTargetSignal,
			Description: `Trace only this signal (it can be an int like 9 or string beginning with "SIG" like "SIGKILL")`,
			Validator:   validateSignal,
		},
		{
			Key:          ParamFailedOnly,
			Alias:        "f",
			DefaultValue: "false",
			Description:  "Show only events where the syscall sending a signal failed",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamKillOnly,
			Alias:        "k",
			DefaultValue: "false",
			Description:  "Show only events issued by kill syscall",
			TypeHint:     params.TypeBool,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}

// validateSignal checks whether the signal argument is empty, contains a number, or starts with "SIG".
// We cannot perform the same check signalStringToInt does, because that is not cross-platform compatible.
func validateSignal(signal string) error {
	if signal == "" {
		return nil
	}
	if strings.HasPrefix(signal, "SIG") {
		return nil
	}
	if _, err := strconv.Atoi(signal); err == nil {
		return nil
	}
	return errors.New("expected a signal number or a signal name starting with 'SIG'")
}
