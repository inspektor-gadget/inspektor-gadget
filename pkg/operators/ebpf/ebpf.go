// Copyright 2024 The Inspektor Gadget authors
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

// Package ebpfoperator provides an operator that is capable of analyzing and running
// an eBFP based gadget.
package ebpfoperator

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tchandler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

const (
	eBPFObjectMediaType = "application/vnd.gadget.ebpf.program.v1+binary"

	typeSplitter = "___"

	ParamIface       = "iface"
	ParamTraceKernel = "trace-pipe"

	// Keep in sync with `include/gadget/kernel_stack_map.h`
	KernelStackMapName       = "ig_kstack"
	KernelStackMapMaxEntries = 10000
	PerfMaxStackDepth        = 127

	kernelTypesVar = "kernelTypes"
)

type param struct {
	*api.Param
	fromEbpf bool
}

// ebpfOperator reads ebpf programs from OCI images and runs them
type ebpfOperator struct{}

func (o *ebpfOperator) Name() string {
	return "ebpf"
}

func (o *ebpfOperator) Description() string {
	return "handles ebpf programs"
}

func (o *ebpfOperator) InstantiateImageOperator(
	gadgetCtx operators.GadgetContext,
	target oras.ReadOnlyTarget,
	desc ocispec.Descriptor,
	paramValues api.ParamValues,
) (
	operators.ImageOperatorInstance, error,
) {
	r, err := oci.GetContentFromDescriptor(gadgetCtx.Context(), target, desc)
	if err != nil {
		return nil, fmt.Errorf("getting ebpf binary: %w", err)
	}
	program, err := io.ReadAll(r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("reading ebpf binary: %w", err)
	}
	r.Close()

	// TODO: do some pre-checks in here, maybe validate hashes, signatures, etc.

	newInstance := &ebpfInstance{
		gadgetCtx: gadgetCtx, // context usually should not be stored, but should we really carry it through all funcs?

		logger:  gadgetCtx.Logger(),
		program: program,

		// Preallocate maps
		tracers:      make(map[string]*Tracer),
		structs:      make(map[string]*Struct),
		snapshotters: make(map[string]*Snapshotter),
		params:       make(map[string]*param),
		mapIters:     make(map[string]*mapIter),

		containers: make(map[string]*containercollection.Container),

		enums:      make([]*enum, 0),
		formatters: make(map[datasource.DataSource][]func(ds datasource.DataSource, data datasource.Data) error),

		vars: make(map[string]*ebpfVar),

		networkTracers: make(map[string]*networktracer.Tracer[api.GadgetData]),
		tcHandlers:     make(map[string]*tchandler.Handler),
		uprobeTracers:  make(map[string]*uprobetracer.Tracer[api.GadgetData]),

		paramValues: paramValues,
	}

	cfg, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing configuration")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("invalid configuration format")
	}
	newInstance.config = v

	err = newInstance.init(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("initializing ebpf gadget: %w", err)
	}

	err = newInstance.evaluateMapParams(paramValues)
	if err != nil {
		return nil, fmt.Errorf("evaluating map params: %w", err)
	}

	return newInstance, nil
}

type ebpfInstance struct {
	mu sync.Mutex

	config *viper.Viper

	program        []byte
	logger         logger.Logger
	collectionSpec *ebpf.CollectionSpec
	collection     *ebpf.Collection

	tracers      map[string]*Tracer
	structs      map[string]*Struct
	snapshotters map[string]*Snapshotter
	mapIters     map[string]*mapIter
	params       map[string]*param
	paramValues  map[string]string

	networkTracers map[string]*networktracer.Tracer[api.GadgetData]
	tcHandlers     map[string]*tchandler.Handler
	uprobeTracers  map[string]*uprobetracer.Tracer[api.GadgetData]

	// map from ebpf variable name to ebpfVar struct
	vars map[string]*ebpfVar

	links []link.Link

	containers map[string]*containercollection.Container

	enums      []*enum
	formatters map[datasource.DataSource][]func(ds datasource.DataSource, data datasource.Data) error

	stackIdMap *ebpf.Map

	gadgetCtx operators.GadgetContext
}

func (i *ebpfInstance) loadSpec() error {
	progReader := bytes.NewReader(i.program)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return fmt.Errorf("loading spec: %w", err)
	}
	i.collectionSpec = spec
	return nil
}

func (i *ebpfInstance) analyze() error {
	prefixLookups := []populateEntry{
		{
			prefixFunc:   hasPrefix(tracerInfoPrefix),
			validator:    i.validateGlobalConstVoidPtrVar,
			populateFunc: i.populateTracer,
		},
		{
			prefixFunc:   hasPrefix(snapshottersPrefix),
			validator:    i.validateGlobalConstVoidPtrVar,
			populateFunc: i.populateSnapshotter,
		},
		{
			prefixFunc:   hasPrefix(paramPrefix),
			validator:    i.validateGlobalConstVoidPtrVar,
			populateFunc: i.populateParam,
		},
		// {
		// 	prefixFunc:   hasPrefix(tracerMapPrefix),
		// 	validator:    i.validateGlobalConstVoidPtrVar,
		// 	populateFunc: i.populateMap,
		// },
		{
			prefixFunc:   hasPrefix(mapIterPrefix),
			validator:    i.validateGlobalConstVoidPtrVar,
			populateFunc: i.populateMapIter,
		},
		{
			prefixFunc: func(s string) (string, bool) {
				// Exceptions for backwards-compatibility
				if s == gadgets.MntNsFilterMapName {
					return gadgets.MntNsFilterMapName, true
				}
				if s == socketenricher.SocketsMapName {
					return socketenricher.SocketsMapName, true
				}
				return "", false
			},
			populateFunc: i.populateMap,
		},
		{
			prefixFunc: func(s string) (string, bool) {
				// Exceptions for backwards-compatibility
				if s == gadgets.FilterByMntNsName {
					return gadgets.FilterByMntNsName, true
				}
				return hasPrefix(varPrefix)(s)
			},
			validator:    nil,
			populateFunc: i.populateVar,
		},
	}

	// Iterate over types and populate the gadget
	it := i.collectionSpec.Types.Iterate()
	for it.Next() {
		for _, entry := range prefixLookups {
			typeName, ok := entry.prefixFunc(it.Type.TypeName())
			if !ok {
				continue
			}
			if entry.validator != nil {
				err := entry.validator(it.Type, strings.TrimPrefix(it.Type.TypeName(), typeName))
				if err != nil {
					i.logger.Debugf("type %q error: %v", it.Type.TypeName(), err)
					continue
				}
			}
			err := entry.populateFunc(it.Type, typeName)
			if err != nil {
				return fmt.Errorf("handling type by prefix %q: %w", typeName, err)
			}
		}
	}

	// Fill param defaults
	err := i.fillParamDefaults()
	if err != nil {
		i.logger.Debugf("error extracting default values for params: %v", err)
	}

	// create map for kernel stack, before initializing converters
	if _, ok := i.collectionSpec.Maps[KernelStackMapName]; ok {
		stackIdMapSpec := ebpf.MapSpec{
			Name:       KernelStackMapName,
			Type:       ebpf.StackTrace,
			KeySize:    4,
			ValueSize:  8 * PerfMaxStackDepth,
			MaxEntries: KernelStackMapMaxEntries,
		}
		i.stackIdMap, err = ebpf.NewMap(&stackIdMapSpec)
		if err != nil {
			return fmt.Errorf("creating stack id map: %w", err)
		}
	}

	// Iterate over programs
	for name, program := range i.collectionSpec.Programs {
		i.logger.Debugf("program %q", name)
		i.logger.Debugf("> type       : %s", program.Type.String())
		i.logger.Debugf("> attachType : %s", program.AttachType.String())
		i.logger.Debugf("> sectionName: %s", program.SectionName)
		i.logger.Debugf("> license    : %s", program.License)
	}
	return nil
}

func (i *ebpfInstance) init(gadgetCtx operators.GadgetContext) error {
	// hack for backward-compability and until we have nicer interfaces available
	gadgetCtx.SetVar("ebpfInstance", i)

	// loadSpec and analyze could be lazily executed, if the gadget has been cached before
	err := i.loadSpec()
	if err != nil {
		return fmt.Errorf("initializing: %w", err)
	}
	err = i.analyze()
	if err != nil {
		return fmt.Errorf("analyzing: %w", err)
	}

	err = i.register(gadgetCtx)
	if err != nil {
		return fmt.Errorf("registering datasources: %w", err)
	}

	err = i.initFormatters(gadgetCtx)
	if err != nil {
		return fmt.Errorf("initializing formatters: %w", err)
	}

	return nil
}

func (i *ebpfInstance) addDataSource(
	gadgetCtx operators.GadgetContext,
	dsType datasource.Type,
	name string,
	size uint32,
	fields []*Field,
) (
	datasource.DataSource, datasource.FieldAccessor, error,
) {
	ds, err := gadgetCtx.RegisterDataSource(dsType, name)
	if err != nil {
		return nil, nil, fmt.Errorf("adding tracer datasource: %w", err)
	}
	staticFields := make([]datasource.StaticField, 0, len(fields))
	for _, field := range fields {
		staticFields = append(staticFields, field)
	}
	accessor, err := ds.AddStaticFields(size, staticFields)
	if err != nil {
		return nil, nil, fmt.Errorf("adding fields for datasource: %w", err)
	}
	return ds, accessor, nil
}

func (i *ebpfInstance) register(gadgetCtx operators.GadgetContext) error {
	// register datasources
	for name, m := range i.tracers {
		ds, accessor, err := i.addDataSource(gadgetCtx, datasource.TypeSingle, name, i.structs[m.structName].Size, i.structs[m.structName].Fields)
		if err != nil {
			return fmt.Errorf("adding datasource: %w", err)
		}
		m.accessor = accessor
		m.ds = ds
	}
	for name, m := range i.snapshotters {
		ds, accessor, err := i.addDataSource(gadgetCtx, datasource.TypeArray, name, i.structs[m.structName].Size, i.structs[m.structName].Fields)
		if err != nil {
			return fmt.Errorf("adding datasource: %w", err)
		}

		m.accessor = accessor
		m.ds = ds

		// Configure fetch-count and fetch-interval annotations to make the
		// combiner operator handle the data correctly
		// TODO: Make this configurable
		m.ds.AddAnnotation(api.FetchIntervalAnnotation, "0")
	}
	for name, m := range i.mapIters {
		fields := make([]*Field, 0)
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, name)
		if err != nil {
			return fmt.Errorf("adding mapiter datasource: %w", err)
		}
		staticFields := make([]datasource.StaticField, 0, len(fields))
		for _, field := range i.structs[m.keyStructName].Fields {
			// check whether role tag needs to be added
			if !slices.Contains(field.Tags, "role:key") {
				field.Tags = append(field.Tags, "role:key")
			}
			staticFields = append(staticFields, field)
		}
		accessor, err := ds.AddStaticFields(i.structs[m.keyStructName].Size, staticFields)
		if err != nil {
			return fmt.Errorf("adding fields for datasource: %w", err)
		}
		m.keyAccessor = accessor

		staticFields = make([]datasource.StaticField, 0, len(fields))
		for _, field := range i.structs[m.valStructName].Fields {
			staticFields = append(staticFields, field)
		}
		accessor, err = ds.AddStaticFields(i.structs[m.valStructName].Size, staticFields)
		if err != nil {
			return fmt.Errorf("adding fields for datasource: %w", err)
		}
		m.valAccessor = accessor

		m.ds = ds
	}
	return nil
}

func (i *ebpfInstance) Name() string {
	return "ebpf"
}

func (i *ebpfInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	res := make(api.Params, 0, len(i.params))
	for _, p := range i.params {
		res = append(res, p.Param)
	}

	// MapIter params
	res = append(res, i.mapParams()...)
	return res
}

func (i *ebpfInstance) Prepare(gadgetCtx operators.GadgetContext) error {
	for ds, formatters := range i.formatters {
		for _, formatter := range formatters {
			formatter := formatter
			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				return formatter(ds, data)
			}, 0)
		}
	}

	// Create network tracers, one for each socket filter program
	// The same applies to uprobe / uretprobe as well.
	for _, p := range i.collectionSpec.Programs {
		switch p.Type {
		case ebpf.Kprobe:
			if strings.HasPrefix(p.SectionName, "uprobe/") ||
				strings.HasPrefix(p.SectionName, "uretprobe/") ||
				strings.HasPrefix(p.SectionName, "usdt/") {
				uprobeTracer, err := uprobetracer.NewTracer[api.GadgetData](gadgetCtx.Logger())
				if err != nil {
					i.Close()
					return fmt.Errorf("creating uprobe tracer: %w", err)
				}
				i.uprobeTracers[p.Name] = uprobeTracer
			}
		case ebpf.SocketFilter:
			if strings.HasPrefix(p.SectionName, "socket") {
				networkTracer, err := networktracer.NewTracer[api.GadgetData]()
				if err != nil {
					i.Close()
					return fmt.Errorf("creating network tracer: %w", err)
				}
				i.networkTracers[p.Name] = networkTracer
			}
		case ebpf.SchedCLS:
			parts := strings.Split(p.SectionName, "/")
			if len(parts) != 3 {
				return fmt.Errorf("invalid section name %q", p.SectionName)
			}
			if parts[0] != "classifier" {
				return fmt.Errorf("invalid section name %q", p.SectionName)
			}

			var direction tchandler.AttachmentDirection

			switch parts[1] {
			case "ingress":
				direction = tchandler.AttachmentDirectionIngress
			case "egress":
				direction = tchandler.AttachmentDirectionEgress
			default:
				return fmt.Errorf("unsupported hook type %q", parts[1])
			}

			handler, err := tchandler.NewHandler(direction)
			if err != nil {
				i.Close()
				return fmt.Errorf("creating tc network tracer: %w", err)
			}

			i.tcHandlers[p.Name] = handler
		}
	}

	if len(i.tcHandlers) > 0 {
		// For now, override enrichment
		gadgetCtx.SetVar("NeedContainerEvents", true)
		i.params["iface"] = &param{
			Param: &api.Param{
				Key:         ParamIface,
				Description: "Network interface to attach to",
			},
		}
	}

	i.params[ParamTraceKernel] = &param{
		Param: &api.Param{
			Key:          ParamTraceKernel,
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
		},
	}
	return nil
}

func (i *ebpfInstance) tracePipe(gadgetCtx operators.GadgetContext) error {
	tracePipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		return fmt.Errorf("opening trace_pipe: %w", err)
	}
	go func() {
		<-gadgetCtx.Context().Done()
		tracePipe.Close()
	}()
	go func() {
		log := gadgetCtx.Logger()

		defer tracePipe.Close()
		scanner := bufio.NewScanner(tracePipe)
		for scanner.Scan() {
			log.Debug(scanner.Text())
		}
	}()
	return nil
}

func (i *ebpfInstance) Start(gadgetCtx operators.GadgetContext) error {
	i.logger.Debugf("starting ebpfInstance")

	gadgets.FixBpfKtimeGetBootNs(i.collectionSpec.Programs)

	parameters := params.Params{}              // used to CopyFromMap
	paramMap := make(map[string]*params.Param) // used for second iteration
	for name, p := range i.params {
		param := apihelpers.ParamToParamDesc(p.Param).ToParam()
		paramMap[name] = param
		parameters = append(parameters, param)
	}
	err := parameters.CopyFromMap(i.paramValues, "")
	if err != nil {
		return fmt.Errorf("parsing parameter values: %w", err)
	}

	if paramMap[ParamTraceKernel].AsBool() {
		err := i.tracePipe(gadgetCtx)
		if err != nil {
			return err
		}
	}

	mapReplacements := make(map[string]*ebpf.Map)
	constReplacements := make(map[string]any)

	// create map for kernel stack
	if i.stackIdMap != nil {
		mapReplacements[KernelStackMapName] = i.stackIdMap
	}

	// Set gadget params
	for name, p := range i.params {
		if !p.fromEbpf {
			continue
		}
		constReplacements[name] = paramMap[name].AsAny()
		i.logger.Debugf("setting param value %q = %v", name, paramMap[name].AsAny())
	}

	for _, v := range i.vars {
		res, ok := gadgetCtx.GetVar(v.name)
		if !ok {
			continue
		}
		i.logger.Debugf("got var %q: %+v", v.name, res)
		switch t := res.(type) {
		case *ebpf.Map:
			if t == nil {
				continue
			}
			i.logger.Debugf("replacing map %q", v.name)
			mapReplacements[v.name] = t
		default:
			if !reflect.TypeOf(res).AssignableTo(v.refType) {
				i.logger.Debugf("variable %q can not be set to type %T (expected %s)", v.name, res, v.refType.Name())
				continue
			}
			i.logger.Debugf("setting var %q to %v", v.name, t)
			constReplacements[v.name] = res
		}
	}

	if err := i.collectionSpec.RewriteConstants(constReplacements); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	i.logger.Debugf("creating ebpf collection")
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	// check if the btfgen operator has stored the kernel types in the context
	if btfSpecI, ok := gadgetCtx.GetVar(kernelTypesVar); ok {
		gadgetCtx.Logger().Debugf("using kernel types from BTFHub")
		btfSpec, ok := btfSpecI.(*btf.Spec)
		if !ok {
			return fmt.Errorf("invalid BTF spec: expected btf.Spec, got %T", btfSpecI)
		}
		opts.Programs.KernelTypes = btfSpec
	}
	collection, err := ebpf.NewCollectionWithOptions(i.collectionSpec, opts)
	if err != nil {
		return fmt.Errorf("creating eBPF collection: %w", err)
	}
	i.collection = collection

	for _, tracer := range i.tracers {
		i.logger.Debugf("starting tracer %q", tracer.mapName)
		go func(tracer *Tracer) {
			err := i.runTracer(gadgetCtx, tracer)
			if err != nil {
				i.logger.Errorf("starting tracer: %w", err)
			}
		}(tracer)
	}

	// Attach programs
	for progName, p := range i.collectionSpec.Programs {
		l, err := i.attachProgram(gadgetCtx, p, i.collection.Programs[progName])
		if err != nil {
			i.Close()
			return fmt.Errorf("attaching eBPF program %q: %w", progName, err)
		}

		if l != nil {
			i.links = append(i.links, l)
		}

		// We need to store iterators' links because we need them to run the programs
		if p.Type == ebpf.Tracing && strings.HasPrefix(p.SectionName, iterPrefix) {
			lIter, ok := l.(*link.Iter)
			if !ok {
				i.Close()
				return fmt.Errorf("link is not an iterator")
			}

			found := false
			for _, snapshotter := range i.snapshotters {
				if _, ok := snapshotter.iterators[progName]; ok {
					snapshotter.links[progName] = &linkSnapshotter{
						link: lIter,
						typ:  p.AttachTo,
					}
					found = true
					break
				}
			}
			if !found {
				i.logger.Warnf("None snapshotter will run iterator %q", progName)
			}
		}
	}

	err = i.runSnapshotters()
	if err != nil {
		i.Close()
		return fmt.Errorf("running snapshotters: %w", err)
	}

	err = i.runMapIterators()
	if err != nil {
		i.Close()
		return fmt.Errorf("running map iterators: %w", err)
	}

	return nil
}

func (i *ebpfInstance) Stop(gadgetCtx operators.GadgetContext) error {
	i.Close()
	return nil
}

func (i *ebpfInstance) Close() {
	if i.collection != nil {
		i.collection.Close()
		i.collection = nil
	}
	for _, l := range i.links {
		gadgets.CloseLink(l)
	}
	i.links = nil

	for _, networkTracer := range i.networkTracers {
		networkTracer.Close()
	}
	for _, handler := range i.tcHandlers {
		handler.Close()
	}
	for _, uprobeTracer := range i.uprobeTracers {
		uprobeTracer.Close()
	}
}

// Using Attacher interface for network tracers for now

func (i *ebpfInstance) AttachContainer(container *containercollection.Container) error {
	i.mu.Lock()
	i.containers[container.Runtime.ContainerID] = container
	i.mu.Unlock()

	for _, networkTracer := range i.networkTracers {
		if err := networkTracer.Attach(container.Pid); err != nil {
			return err
		}
	}

	if ifaceName := i.paramValues[ParamIface]; ifaceName == "" {
		for _, handler := range i.tcHandlers {
			if err := handler.AttachContainer(container); err != nil {
				return err
			}
		}
	}

	for _, handler := range i.uprobeTracers {
		if err := handler.AttachContainer(container); err != nil {
			return err
		}
	}

	return nil
}

func (i *ebpfInstance) DetachContainer(container *containercollection.Container) error {
	i.mu.Lock()
	delete(i.containers, container.Runtime.ContainerID)
	i.mu.Unlock()

	for _, networkTracer := range i.networkTracers {
		if err := networkTracer.Detach(container.Pid); err != nil {
			return err
		}
	}

	if ifaceName := i.paramValues[ParamIface]; ifaceName == "" {
		for _, handler := range i.tcHandlers {
			if err := handler.DetachContainer(container); err != nil {
				return err
			}
		}
	}

	for _, uTracer := range i.uprobeTracers {
		if err := uTracer.DetachContainer(container); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	operators.RegisterOperatorForMediaType(eBPFObjectMediaType, &ebpfOperator{})
}
