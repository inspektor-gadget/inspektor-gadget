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
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type gadget struct {
	*gadgets.GadgetWithParams
}

func (g *gadget) Name() string {
	return "signal"
}

func (g *gadget) Category() string {
	return gadgets.CategoryTrace
}

func (g *gadget) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *gadget) Description() string {
	return "Trace signals received by processes"
}

func (g *gadget) Parser() parser.Parser {
	return parser.NewParser(types.GetColumns())
}

func (g *gadget) EventPrototype() any {
	return &types.Event{}
}

const (
	ParamPID          = "pid"
	ParamTargetSignal = "signal"
	ParamFailedOnly   = "failed-only"
	ParamKillOnly     = "kill-only"
)

func NewGadget() *gadget {
	paramsDescs := &params.ParamDescs{
		{
			Key:          ParamPID,
			DefaultValue: "0",
			Description:  "Show only signal sent by this particular PID",
			Validator:    params.ValidateNumber,
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
	return &gadget{
		GadgetWithParams: gadgets.NewGadgetWithParams(paramsDescs),
	}
}

func init() {
	gadgetregistry.RegisterGadget(NewGadget())
}

func validateSignal(signal string) error {
	_, err := signalStringToInt(signal)
	return err
}

func signalStringToInt(signal string) (int32, error) {
	// There are three possibilities:
	// 1. Either user did not give a signal, thus the argument is empty string.
	// 2. Or signal begins with SIG.
	// 3. Or signal is a string which contains an integer.
	if signal == "" {
		return 0, nil
	}

	if strings.HasPrefix(signal, "SIG") {
		signalNum := unix.SignalNum(signal)
		if signalNum == 0 {
			return 0, fmt.Errorf("no signal found for %q", signal)
		}

		return int32(signalNum), nil
	}

	signalNum, err := strconv.ParseInt(signal, 10, 32)

	return int32(signalNum), err
}
