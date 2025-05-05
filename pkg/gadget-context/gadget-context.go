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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
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
	name                     string
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

	// useInstance, if set, will try to work with existing gadget instances on the server
	useInstance      bool
	requestExtraInfo bool

	lock             sync.Mutex
	dataSources      map[string]datasource.DataSource
	dataOperators    []operators.DataOperator
	vars             map[string]any
	params           []*api.Param
	prepareCallbacks []func()
	loaded           bool
	imageName        string
	metadata         []byte
	orasTarget       oras.ReadOnlyTarget
}

func NewBuiltIn(
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
		requestExtraInfo:         false,

		dataSources: make(map[string]datasource.DataSource),
		vars:        make(map[string]any),
	}
}

func New(
	ctx context.Context,
	imageName string,
	options ...Option,
) *GadgetContext {
	gCtx, cancel := context.WithCancel(ctx)
	gadgetContext := &GadgetContext{
		ctx:    gCtx,
		cancel: cancel,
		args:   []string{},
		logger: logger.DefaultLogger(),

		imageName:   imageName,
		dataSources: make(map[string]datasource.DataSource),
		vars:        make(map[string]any),
		// dataOperators: operators.GetDataOperators(),
	}
	for _, option := range options {
		option(gadgetContext)
	}
	return gadgetContext
}

func (c *GadgetContext) ID() string {
	return c.id
}

func (c *GadgetContext) ExtraInfo() bool {
	return c.requestExtraInfo
}

func (c *GadgetContext) Name() string {
	return c.name
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

func (c *GadgetContext) ImageName() string {
	return c.imageName
}

func (c *GadgetContext) DataOperators() []operators.DataOperator {
	return slices.Clone(c.dataOperators)
}

func (c *GadgetContext) IsRemoteCall() bool {
	val := c.ctx.Value(remoteKey)
	if val == nil {
		return false
	}
	bVal, ok := val.(bool)
	if !ok {
		c.logger.Errorf("invalid type of variable %s on context, expected bool, got %T", remoteKey, val)
		return false
	}
	return bVal
}

func (c *GadgetContext) UseInstance() bool {
	return c.useInstance
}

func (c *GadgetContext) RegisterDataSource(t datasource.Type, name string) (datasource.DataSource, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	options := make([]datasource.DataSourceOption, 0)
	if cfg, ok := c.GetVar("config"); ok {
		if v, ok := cfg.(*viper.Viper); ok {
			sub := v.Sub("datasources." + name)
			if sub != nil {
				options = append(options, datasource.WithConfig(sub))
			}
		}
	}

	ds, err := datasource.New(t, name, options...)
	if err != nil {
		return nil, fmt.Errorf("creating DataSource: %w", err)
	}

	c.dataSources[name] = ds
	return ds, nil
}

func (c *GadgetContext) getDataSources(all bool) map[string]datasource.DataSource {
	c.lock.Lock()
	defer c.lock.Unlock()

	ret := maps.Clone(c.dataSources)
	for name, ds := range ret {
		// Don't forward unreferenced data sources if all is false
		if !all && !ds.IsReferenced() {
			delete(ret, name)
		}
	}
	return ret
}

func (c *GadgetContext) GetDataSources() map[string]datasource.DataSource {
	return c.getDataSources(false)
}

func (c *GadgetContext) GetAllDataSources() map[string]datasource.DataSource {
	return c.getDataSources(true)
}

func (c *GadgetContext) SetVar(varName string, value any) {
	c.vars[varName] = value
}

func (c *GadgetContext) GetVar(varName string) (any, bool) {
	res, ok := c.vars[varName]
	return res, ok
}

func (c *GadgetContext) GetVars() map[string]any {
	return maps.Clone(c.vars)
}

func (c *GadgetContext) Params() []*api.Param {
	return slices.Clone(c.params)
}

func (c *GadgetContext) SetParams(params []*api.Param) {
	c.params = append(c.params, params...)
}

func (c *GadgetContext) SetMetadata(m []byte) {
	c.metadata = m
}

func (c *GadgetContext) SerializeGadgetInfo(extraInfo bool) (*api.GadgetInfo, error) {
	gi := &api.GadgetInfo{
		Name:      "",
		Id:        c.id,
		ImageName: c.ImageName(),
		Metadata:  c.metadata,
		Params:    c.params,
	}

	for _, ds := range c.GetDataSources() {
		di := &api.DataSource{
			Id:          0,
			Type:        uint32(ds.Type()),
			Name:        ds.Name(),
			Fields:      ds.Fields(),
			Tags:        ds.Tags(),
			Annotations: ds.Annotations(),
		}
		if ds.ByteOrder() == binary.BigEndian {
			di.Flags |= api.DataSourceFlagsBigEndian
		}
		gi.DataSources = append(gi.DataSources, di)
	}

	if c.ExtraInfo() && extraInfo {
		gi.ExtraInfo = &api.ExtraInfo{
			Data: make(map[string]*api.GadgetInspectAddendum),
		}

		for k, v := range c.GetVars() {
			if !strings.HasPrefix(k, "extraInfo.") {
				continue
			}
			for k, v := range v.(*api.ExtraInfo).Data {
				gi.ExtraInfo.Data[strings.TrimPrefix(k, "extraInfo.")] = v
			}
		}
	}
	return gi, nil
}

func (c *GadgetContext) LoadGadgetInfo(info *api.GadgetInfo, paramValues api.ParamValues, run bool, extraInfo *api.ExtraInfo) error {
	c.lock.Lock()
	if c.loaded {
		// TODO: verify that info matches what we previously loaded
		c.lock.Unlock()
		return nil
	}

	c.id = info.Id
	c.metadata = info.Metadata
	c.dataSources = make(map[string]datasource.DataSource)
	for _, inds := range info.DataSources {
		ds, err := datasource.NewFromAPI(inds)
		if err != nil {
			c.lock.Unlock()
			return fmt.Errorf("creating DataSource from API: %w", err)
		}
		c.dataSources[inds.Name] = ds
	}

	// Skip params coming from the server if we're attaching; it's too late to provide params
	// for the gadget instance so only local operators should be evaluated
	if !c.useInstance {
		c.params = info.Params
	}
	c.loaded = true
	c.lock.Unlock()

	c.Logger().Debug("loaded gadget info")

	if c.metadata != nil {
		v := viper.New()
		v.SetConfigType("yaml")
		err := v.ReadConfig(bytes.NewReader(c.metadata))
		if err != nil {
			return fmt.Errorf("unmarshalling metadata: %w", err)
		}
		c.logger.Debugf("loaded metadata as config")
		c.SetVar("config", v)
	}

	// After loading gadget info, start local operators as well
	localOperators, err := c.initAndPrepareOperators(paramValues)
	if err != nil {
		return fmt.Errorf("initializing local operators: %w", err)
	}

	if run {
		if err := c.start(localOperators); err != nil {
			return fmt.Errorf("starting local operators: %w", err)
		}

		c.Logger().Debugf("running...")

		go func() {
			// TODO: Client shouldn't need to wait for the timeout. It should be
			// managed only on the server side.
			WaitForTimeoutOrDone(c)
			c.stop(localOperators)
		}()
	}

	if c.ExtraInfo() && extraInfo != nil {
		for k, v := range extraInfo.Data {
			// k is in the form of "wasm.upcalls", "ebpf.sections", etc.
			prefix := strings.Split(k, ".")[0]
			ei, ok := c.GetVar("extraInfo." + prefix)
			if !ok {
				ei = &api.ExtraInfo{
					Data: make(map[string]*api.GadgetInspectAddendum),
				}
				c.SetVar("extraInfo."+prefix, ei)
			}
			ei.(*api.ExtraInfo).Data[k] = v
		}
	}
	return nil
}

func (c *GadgetContext) OrasTarget() oras.ReadOnlyTarget {
	return c.orasTarget
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
