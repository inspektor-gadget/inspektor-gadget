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

/*
Package gadgetcontext handles initializing gadgets and installed operators before
handing them over to a specified runtime.
*/
package gadgetcontext

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// GadgetContext handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime.
type GadgetContext struct {
	ctx                      context.Context
	cancel                   context.CancelFunc
	id                       string
	gadget                   gadgets.GadgetDesc
	gadgetParams             *params.Params
	args                     []string
	runtime                  runtime.Runtime
	runtimeParams            *params.Params
	parser                   parser.Parser
	operators                operators.Operators
	operatorsParamCollection params.Collection
	logger                   logger.Logger
	result                   []byte
	resultError              error
	timeout                  time.Duration
	gadgetInfo               *runTypes.GadgetInfo

	lock             sync.Mutex
	router           datasource.Router
	dataSources      map[string]datasource.DataSource
	vars             map[string]any
	params           []*api.Param
	prepareCallbacks []func()
	loaded           bool
}

func New(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	runtimeParams *params.Params,
	gadget gadgets.GadgetDesc,
	gadgetParams *params.Params,
	args []string,
	operatorsParamCollection params.Collection,
	parser parser.Parser,
	logger logger.Logger,
	timeout time.Duration,
	gadgetInfo *runTypes.GadgetInfo,
) *GadgetContext {
	gCtx, cancel := context.WithCancel(ctx)

	return &GadgetContext{
		ctx:                      gCtx,
		cancel:                   cancel,
		id:                       id,
		runtime:                  runtime,
		runtimeParams:            runtimeParams,
		gadget:                   gadget,
		gadgetParams:             gadgetParams,
		args:                     args,
		parser:                   parser,
		logger:                   logger,
		operators:                operators.GetOperatorsForGadget(gadget),
		operatorsParamCollection: operatorsParamCollection,
		timeout:                  timeout,
		gadgetInfo:               gadgetInfo,

		dataSources: make(map[string]datasource.DataSource),
		vars:        make(map[string]any),
	}
}

func NewSimple(
	ctx context.Context,
	url string,
	logger logger.Logger,
	ociParams *params.Params,
	gadgetParams *params.Params,
) *GadgetContext {
	gCtx, cancel := context.WithCancel(ctx)

	operatorsParamCollection := make(params.Collection)
	operatorsParamCollection["oci"] = ociParams

	return &GadgetContext{
		ctx:                      gCtx,
		cancel:                   cancel,
		args:                     []string{url},
		logger:                   logger,
		operatorsParamCollection: operatorsParamCollection,
		gadgetParams:             gadgetParams,

		dataSources: make(map[string]datasource.DataSource),
		vars:        make(map[string]any),
	}
}

func (c *GadgetContext) ID() string {
	return c.id
}

func (c *GadgetContext) Context() context.Context {
	return c.ctx
}

func (c *GadgetContext) Cancel() {
	c.cancel()
}

func (c *GadgetContext) Parser() parser.Parser {
	return c.parser
}

func (c *GadgetContext) Runtime() runtime.Runtime {
	return c.runtime
}

func (c *GadgetContext) RuntimeParams() *params.Params {
	return c.runtimeParams
}

func (c *GadgetContext) GadgetDesc() gadgets.GadgetDesc {
	return c.gadget
}

func (c *GadgetContext) Operators() operators.Operators {
	return c.operators
}

func (c *GadgetContext) Logger() logger.Logger {
	return c.logger
}

func (c *GadgetContext) GadgetParams() *params.Params {
	return c.gadgetParams
}

func (c *GadgetContext) Args() []string {
	return c.args
}

func (c *GadgetContext) OperatorsParamCollection() params.Collection {
	return c.operatorsParamCollection
}

func (c *GadgetContext) Timeout() time.Duration {
	return c.timeout
}

func (c *GadgetContext) GadgetInfo() *runTypes.GadgetInfo {
	return c.gadgetInfo
}

func (c *GadgetContext) RegisterDataSource(t datasource.Type, name string) (datasource.DataSource, error) {
	ds := datasource.New(t, name)
	c.dataSources[name] = ds
	return ds, nil
}

func (c *GadgetContext) GetDataSources() map[string]datasource.DataSource {
	return maps.Clone(c.dataSources)
}

func (c *GadgetContext) SetRouter(router datasource.Router) {
	c.router = router
}

func (c *GadgetContext) GetSinkForDataSource(source datasource.DataSource) datasource.Sink {
	if c.router == nil {
		return nil
	}
	return c.router.GetSinkForDataSource(source)
}

func (c *GadgetContext) OnPrepare(cb func()) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.prepareCallbacks = append(c.prepareCallbacks, cb)
}

func (c *GadgetContext) CallPrepareCallbacks() {
	// Make a copy of prepareCallbacks first, so we're out of the lock afterward, since
	// callbacks might need locks as well
	c.lock.Lock()
	cbs := slices.Clone(c.prepareCallbacks)
	c.lock.Unlock()
	for _, p := range cbs {
		p()
	}
}

func (c *GadgetContext) SetVar(varName string, value any) {
	c.vars[varName] = value
}

func (c *GadgetContext) GetVar(varName string) (any, bool) {
	res, ok := c.vars[varName]
	return res, ok
}

func (c *GadgetContext) GetVars() map[string]any {
	res := make(map[string]any)
	for k, v := range c.vars {
		res[k] = v
	}
	return res
}

func (c *GadgetContext) RegisterParam(param *api.Param) error {
	c.params = append(c.params, param)
	return nil
}

func (c *GadgetContext) Params() []*api.Param {
	return slices.Clone(c.params)
}

func (c *GadgetContext) SerializeGadgetInfo() (*api.GadgetInfo, error) {
	fmt.Printf("SerializeGadgetInfo\n")

	// metadataBytes, err := yaml.Marshal(c.metadata)
	// if err != nil {
	// 	return nil, fmt.Errorf("marshaling metadata: %w", err)
	// }

	gi := &api.GadgetInfo{
		Name:        "",
		Url:         "",
		DataSources: nil,
		Annotations: nil,
		Metadata:    nil,
		Params:      c.params,
	}

	for _, ds := range c.GetDataSources() {
		di := &api.DataSource{
			DataSourceID: 0,
			Name:         ds.Name(),
			Fields:       ds.Fields(),
			Tags:         nil,
			Annotations:  nil,
		}
		gi.DataSources = append(gi.DataSources, di)
	}

	return gi, nil
}

func (c *GadgetContext) LoadGadgetInfo(info *api.GadgetInfo) error {
	c.lock.Lock()
	if c.loaded {
		// TODO: verify that info matches what we previously loaded
		c.lock.Unlock()
		return nil
	}

	c.dataSources = make(map[string]datasource.DataSource)
	for _, inds := range info.DataSources {
		ds, err := datasource.NewFromAPI(inds)
		if err != nil {
			c.lock.Unlock()
			return fmt.Errorf("creating DataSource from API: %w", err)
		}
		c.dataSources[inds.Name] = ds
	}
	c.params = info.Params
	c.lock.Unlock()

	c.CallPrepareCallbacks()
	return nil
}

func WithTimeoutOrCancel(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func WaitForTimeoutOrDone(c gadgets.GadgetContext) {
	ctx, cancel := WithTimeoutOrCancel(c.Context(), c.Timeout())
	defer cancel()
	<-ctx.Done()
}
