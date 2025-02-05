// Copyright 2022-2024 The Inspektor Gadget authors
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

package runtime

import (
	"context"
	"time"

	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	// NumRunTargets is the number of targets that the gadget will run on
	NumRunTargets = "n-run-targets"
)

type GadgetContext interface {
	ID() string
	Name() string
	Parser() parser.Parser
	GadgetDesc() gadgets.GadgetDesc
	Context() context.Context
	Operators() operators.Operators
	Logger() logger.Logger
	RuntimeParams() *params.Params
	GadgetParams() *params.Params
	Args() []string
	OperatorsParamCollection() params.Collection
	Timeout() time.Duration
	UseInstance() bool

	Cancel()
	ImageName() string
	RegisterDataSource(datasource.Type, string) (datasource.DataSource, error)
	GetDataSources() map[string]datasource.DataSource
	GetAllDataSources() map[string]datasource.DataSource
	SetVar(string, any)
	GetVar(string) (any, bool)
	SerializeGadgetInfo() (*api.GadgetInfo, error)
	LoadGadgetInfo(info *api.GadgetInfo, paramValues api.ParamValues, run bool) error
	Params() []*api.Param
	SetMetadata([]byte)
	SetParams([]*api.Param)
	DataOperators() []operators.DataOperator
	OrasTarget() oras.ReadOnlyTarget
	IsRemoteCall() bool

	Run(paramValues api.ParamValues) error
	PrepareGadgetInfo(paramValues api.ParamValues) error
}

// GadgetResult contains the (optional) payload and error of a gadget run for a node
type GadgetResult struct {
	Payload []byte
	Error   error
}

type CombinedGadgetResult map[string]*GadgetResult

func (r CombinedGadgetResult) Err() error {
	c := &combinedErrors{}
	for _, result := range r {
		if result != nil && result.Error != nil {
			c.errs = append(c.errs, result.Error)
		}
	}
	if len(c.errs) > 0 {
		return c
	}
	return nil
}

type combinedErrors struct {
	errs []error
}

func (e *combinedErrors) Error() string {
	var b []byte
	for i, err := range e.errs {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, err.Error()...)
	}
	return string(b)
}

func (e *combinedErrors) Unwrap() []error {
	return e.errs
}

// Runtime is the interface for gadget runtimes. Runtimes are used to control the lifecycle of gadgets either locally
// or remotely.
type Runtime interface {
	Init(globalRuntimeParams *params.Params) error
	Close() error
	GlobalParamDescs() params.ParamDescs
	ParamDescs() params.ParamDescs

	// GetGadgetInfo returns information about the gadget and used operators; this info potentially comes
	// from a cache
	GetGadgetInfo(gadgetCtx GadgetContext, runtimeParams *params.Params, paramValueMap api.ParamValues) (*api.GadgetInfo, error)

	RunBuiltInGadget(gadgetCtx GadgetContext) (CombinedGadgetResult, error)
	RunGadget(gadgetCtx GadgetContext, runtimeParams *params.Params, paramValueMap api.ParamValues) error
	GetCatalog() (*Catalog, error)
	SetDefaultValue(params.ValueHint, string)
	GetDefaultValue(params.ValueHint) (string, bool)
}
