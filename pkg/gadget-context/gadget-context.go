// Copyright 2022-2025 The Inspektor Gadget authors
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
	"sort"
	"strings"
	"sync"
	"text/template"
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

const customParamsKey = "params.custom"

// GadgetContext handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime.
type GadgetContext struct {
	ctx           context.Context
	cancel        context.CancelFunc
	id            string
	name          string
	args          []string
	runtime       runtime.Runtime
	runtimeParams *params.Params
	parser        parser.Parser
	logger        logger.Logger
	result        []byte
	resultError   error
	timeout       time.Duration

	// useInstance, if set, will try to work with existing gadget instances on the server
	useInstance      bool
	requestExtraInfo bool

	lock           sync.Mutex
	dataSources    map[string]datasource.DataSource
	dataOperators  []operators.DataOperator
	localOperators []operators.DataOperatorInstance
	vars           map[string]any
	params         []*api.Param
	paramValues    api.ParamValues
	loaded         bool
	imageName      string
	metadata       []byte
	orasTarget     oras.ReadOnlyTarget
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

func (c *GadgetContext) Logger() logger.Logger {
	return c.logger
}

func (c *GadgetContext) Args() []string {
	return c.args
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

func (c *GadgetContext) IsClient() bool {
	val := c.ctx.Value(clientKey)
	if val == nil {
		return false
	}
	bVal, ok := val.(bool)
	if !ok {
		c.logger.Errorf("invalid type of variable %s on context, expected bool, got %T", clientKey, val)
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

// processCustomParams extracts and processes custom parameters from the
// metadata file. It processes the parameters, applies any parameter values and
// template processing to the metadata file, and adds the processed parameters
// to the context via SetParams.
func (c *GadgetContext) processCustomParams(v *viper.Viper, paramValues api.ParamValues) error {
	params := make([]*api.Param, 0)

	// Safeguard
	if paramValues == nil {
		paramValues = make(api.ParamValues)
	}

	customParams := v.Sub(customParamsKey)
	if customParams == nil {
		return nil
	}

	for k := range v.GetStringMap(customParamsKey) {
		c.Logger().Debugf("evaluating custom param %q", k)
		paramSub := customParams.Sub(k)
		valuesSub := paramSub.Sub("values")
		if valuesSub == nil && !paramSub.IsSet("patch") {
			c.Logger().Debugf("custom param %q has no values and no global patch set", k)
			continue
		}
		p := &api.Param{
			Key:          k,
			Description:  paramSub.GetString("description"),
			Prefix:       "custom.",
			DefaultValue: paramSub.GetString("defaultValue"),
			Alias:        paramSub.GetString("alias"),
		}
		for value := range paramSub.GetStringMap("values") {
			p.PossibleValues = append(p.PossibleValues, value)
		}
		params = append(params, p)

		// Evaluate, if set
		if val, ok := paramValues["custom."+k]; ok {
			valSubPath := "values." + val + "."
			if !paramSub.IsSet(valSubPath+"patch") && paramSub.IsSet("patch") {
				// Use generic patch fallback
				valSubPath = ""
			}

			c.Logger().Debugf("applying custom param %q", k)

			valSub := paramSub.Sub(valSubPath + "patch")
			if valSub == nil {
				continue
			}

			// Apply templates
			replacements := make(map[string]string)
			for _, k1 := range valSub.AllKeys() {
				v1 := valSub.Get(k1)
				if s, ok := v1.(string); ok {
					tpl, err := template.New(k1).Parse(s)
					if err != nil {
						return fmt.Errorf("parsing custom param %q value %q: %q cannot be parsed as template: %w", k, val, k1, err)
					}
					out := bytes.NewBuffer(nil)
					err = tpl.Execute(out, map[string]any{
						"getParamValue": func(key string) string { return paramValues[key] },
						"getConfig": func(key string) string {
							return v.GetString(strings.ToLower(key))
						},
					})
					if err != nil {
						return fmt.Errorf("evaluating custom param %q value %q template for %q: %w", k, val, k1, err)
					}
					if tplOut := out.String(); tplOut != s {
						c.Logger().Debugf("custom param %q value %q: replacing %q's value %q with %q", k, valSubPath, k1, s, tplOut)
						replacements[k1] = tplOut
					}
				}
			}

			for k1, v1 := range replacements {
				paramSub.Set(valSubPath+"patch."+k1, v1)
			}

			applyMap := paramSub.GetStringMap(valSubPath + "patch")

			// Prevent recursive patching of customparams
			delete(applyMap, customParamsKey)

			c.Logger().Debugf("applying custom param %+v", applyMap)

			// Merge with config
			err := v.MergeConfigMap(applyMap)
			if err != nil {
				return fmt.Errorf("merging custom param %q value %q: %w", k, valSubPath, err)
			}

			c.Logger().Debugf("map now %+v", v)
		}
	}

	// Add the processed custom params
	c.SetParams(params)

	return nil
}

func (c *GadgetContext) SetMetadata(m []byte) error {
	c.metadata = m

	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(bytes.NewReader(c.metadata))
	if err != nil {
		return fmt.Errorf("unmarshalling metadata: %w", err)
	}
	c.logger.Debugf("loaded metadata as config")

	// Extract and process custom params
	err = c.processCustomParams(v, c.paramValues)
	if err != nil {
		return fmt.Errorf("processing custom params: %w", err)
	}

	c.SetVar("config", v)
	return nil
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
	sort.Slice(gi.DataSources, func(i, j int) bool {
		return gi.DataSources[i].Name < gi.DataSources[j].Name
	})

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

	// After loading gadget info, start local operators as well
	err := c.instantiateOperators(paramValues)
	if err != nil {
		return fmt.Errorf("initializing local operators: %w", err)
	}

	if run {
		if err := c.preStart(); err != nil {
			return fmt.Errorf("pre-starting operators: %w", err)
		}
		if err := c.start(); err != nil {
			return fmt.Errorf("starting local operators: %w", err)
		}
		c.Logger().Debugf("running...")
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

func (c *GadgetContext) StopLocalOperators() {
	if c.localOperators == nil {
		return
	}
	c.stop()
	c.postStop()
	c.localOperators = nil
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
