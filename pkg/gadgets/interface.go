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

package gadgets

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

// GadgetType defines how a gadget is actually run
type GadgetType string

const (
	TypeTrace          GadgetType = "trace"          // Normal trace gadgets
	TypeTraceIntervals GadgetType = "traceIntervals" // top gadgets expecting arrays of events
	TypeOneShot        GadgetType = "oneShot"        // Gadgets that only fetch results
	TypeProfile        GadgetType = "profile"        // Gadgets that run until the user stops, or it times out and then shows results
	TypeOther          GadgetType = "other"
)

func (t GadgetType) CanSort() bool {
	return t == TypeOneShot || t == TypeTraceIntervals
}

func (t GadgetType) IsPeriodic() bool {
	return t == TypeTraceIntervals
}

// GadgetDesc is the main interface for handling gadgets
type GadgetDesc interface {
	// Name provides the name of the gadget. This is used for the calling the gadget, auto-creating the cobra commands,
	// logging, etc.
	Name() string

	// Description provides a short description of the gadget. This is used for a quick help in cobra, help,
	// web-interface etc.
	Description() string

	// Category is used for cobra sub-commands and categories on the web interface.
	Category() string

	// Type is used to differentiate between how gadgets are run. The type essentially controls the workflow of the
	// gadget.
	Type() GadgetType

	// ParamDescs returns a map of configuration parameters. These hold also default values, descriptions, validators and
	// so on. Used whenever a gadget is called somehow. Auto-creates parameters for cobra as well.
	ParamDescs() params.ParamDescs

	// Parser returns a parser.Parser instance that can handle events and do certain operations on them
	// (sorting, filtering, etc.) without the caller needing to know about the underlying types.
	Parser() parser.Parser

	// EventPrototype returns a blank event. Useful for checking for interfaces on it (see operators).
	EventPrototype() any
}

// Optional extensions to GadgetDesc

// GadgetDescSkipParams / SkipParams() can define params that a gadget, runtime or operators never can use in
// combination with this gadget. Currently, this is used to not allow to specify for example a container name
// when the gadget is working inside the kubernetes environment and using the netns (as results could be ambiguous in
// that case).
type GadgetDescSkipParams interface {
	SkipParams() []params.ValueHint
}

type OutputFormats map[string]OutputFormat

// OutputFormat can hold alternative output formats for a gadget. Whenever
// such a format is used, the result of the gadget will be passed to the Transform()
// function and returned to the user.
type OutputFormat struct {
	Name                   string                    `json:"name"`
	Description            string                    `json:"description"`
	RequiresCombinedResult bool                      `json:"requiresCombinedResult"`
	Transform              func(any) ([]byte, error) `json:"-"`
}

// Append appends the OutputFormats given in other to of
func (of OutputFormats) Append(other OutputFormats) {
	for k, v := range other {
		of[k] = v
	}
}

// GadgetOutputFormats can be implemented together with the gadget interface
// to register alternative output formats that are used in combination with
// the GadgetResult interface. The defaultFormatKey MUST match the key of
// an entry in the supportedFormats map
type GadgetOutputFormats interface {
	OutputFormats() (supportedFormats OutputFormats, defaultFormatKey string)
}

// GadgetDescCustomParser can be implemented by gadgets that want to provide a custom parser
// dependent on the parameters and arguments.
type GadgetDescCustomParser interface {
	CustomParser(*params.Params, []string) (parser.Parser, error)
}

// Printer is implemented by objects that can print information, like frontends.
type Printer interface {
	Output(payload string)
	Logf(severity logger.Level, fmt string, params ...any)
}

type GadgetJSONConverter interface {
	JSONConverter(params *params.Params, p Printer) func(ev any)
}

type GadgetJSONPrettyConverter interface {
	JSONPrettyConverter(params *params.Params, p Printer) func(ev any)
}

type GadgetYAMLConverter interface {
	YAMLConverter(params *params.Params, p Printer) func(ev any)
}

type EventHandlerSetter interface {
	SetEventHandler(handler any)
}

type EventHandlerArraySetter interface {
	SetEventHandlerArray(handler any)
}

type EventEnricherSetter interface {
	SetEventEnricher(func(ev any) error)
}

// RunGadget is an interface that will be implemented by gadgets that are run in
// the background and emit events as soon as they occur.
type RunGadget interface {
	// Run is expected to run the gadget and emits the events using the
	// EventHandler. This function is expected to be blocking and return only
	// when the context is done, after which the gadget should clean up all
	// resources. Notice that this function will be called after operators are
	// installed.
	Run(GadgetContext) error
}

// RunWithResultGadget is an alternative to RunGadget that returns the result
// of the gadget only at the end of its execution.
type RunWithResultGadget interface {
	// RunWithResult follows the same rules as Run() but instead of using an
	// EventHandler to emit the events, it returns the result of the gadget as a
	// byte array after the context is done.
	RunWithResult(GadgetContext) ([]byte, error)
}

// InitCloseGadget is an optional interface that can be implemented by gadgets
// that needs to be initialized before the operators are installed. An example
// of this is when the gadget needs to be kept up-to-date with the containers
// that need to be traced, as the operators will start sending notifications of
// this as soon as it is installed. So, the gadget needs to be initialized and
// ready to receive those notifications before the operators are installed.
type InitCloseGadget interface {
	// Init is expected to initialize the gadget. It will be called right before
	// the operators are installed, and also before Run() is called (which is
	// done after the operators are installed, see the Gadget interface).
	Init(GadgetContext) error

	// Close is expected to clean up all the resources allocated by the gadget.
	// It will be called after Run() returns and after the operators have been
	// uninstalled.
	// TODO: We should pass the gadget context to Close().
	Close()
}

type Gadget any

// GadgetInstantiate is the same interface as Gadget but adds one call to instantiate an actual
// tracer
type GadgetInstantiate interface {
	GadgetDesc

	// NewInstance creates a new gadget and returns it; the tracer should be allocated and configured but
	// should not run any code that depends on cleanup
	NewInstance() (Gadget, error)
}
