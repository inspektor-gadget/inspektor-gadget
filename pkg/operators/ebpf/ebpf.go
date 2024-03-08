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
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tchandler"
)

const (
	eBPFObjectMediaType = "application/vnd.gadget.ebpf.program.v1+binary"

	typeSplitter = "___"
)

// ebpfOperator reads ebpf programs from OCI images and runs them
type ebpfOperator struct{}

func (o *ebpfOperator) Name() string {
	return "ebpf"
}

func (o *ebpfOperator) Description() string {
	return "handles ebpf programs"
}

func (o *ebpfOperator) InstantiateImageOperator(gadgetCtx operators.GadgetContext, desc ocispec.Descriptor) (
	operators.ImageOperatorInstance, error,
) {
	r, err := oci.GetContentFromDescriptor(gadgetCtx.Context(), desc)
	if err != nil {
		return nil, fmt.Errorf("getting ebpf binary: %w", err)
	}
	program, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading binary: %w", err)
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
		params:       make(map[string]*api.Param),

		containers: make(map[string]*containercollection.Container),

		vars: make(map[string]*ebpfVar),

		networkTracers: make(map[string]*networktracer.Tracer[api.GadgetData]),
		tcHandlers:     make(map[string]*tchandler.Handler),
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
	params       map[string]*api.Param

	networkTracers map[string]*networktracer.Tracer[api.GadgetData]
	tcHandlers     map[string]*tchandler.Handler

	// Network interface to attach the TC programs to. If set, the gadget won't attach to any
	// container. // TODO: per-program interfaces?
	ifaceName string

	// map from ebpf variable name to ebpfVar struct
	vars map[string]*ebpfVar

	links             []link.Link
	linksSnapshotters []*linkSnapshotter

	containers map[string]*containercollection.Container

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
			prefixFunc: func(s string) (string, bool) {
				// Exceptions for backwards-compatibility
				if s == gadgets.MntNsFilterMapName {
					return gadgets.MntNsFilterMapName, true
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
			if prefix, ok := entry.prefixFunc(it.Type.TypeName()); ok {
				if entry.validator != nil {
					ok, err := entry.validator(it.Type, strings.TrimPrefix(it.Type.TypeName(), prefix))
					if !ok {
						if err != nil {
							i.logger.Debugf("type %q error: %v", it.Type.TypeName(), err)
						}
						continue
					}
				}
				err := entry.populateFunc(it.Type, prefix) // strings.TrimPrefix(it.Type.TypeName(), prefix)
				if err != nil {
					return fmt.Errorf("handling type by prefix %q: %w", prefix, err)
				}
			}
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

	return i.register(gadgetCtx)
}

func (i *ebpfInstance) register(gadgetCtx operators.GadgetContext) error {
	// register datasources
	for _, m := range i.tracers {
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeEvent, m.MapName)
		if err != nil {
			return fmt.Errorf("adding tracer datasource: %w", err)
		}
		fields := make(datasource.Fields, 0, len(i.structs[m.StructName].Fields))
		for _, field := range i.structs[m.StructName].Fields {
			fields = append(fields, field)
		}
		m.accessor, err = ds.AddStaticFields(i.structs[m.StructName].Size, fields)
		if err != nil {
			return fmt.Errorf("adding fields for datasource: %w", err)
		}
		m.ds = ds
	}
	for _, m := range i.snapshotters {
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeEvent, m.StructName)
		if err != nil {
			return fmt.Errorf("adding tracer datasource: %w", err)
		}
		fields := make(datasource.Fields, 0, len(i.structs[m.StructName].Fields))
		for _, field := range i.structs[m.StructName].Fields {
			fields = append(fields, field)
		}
		m.accessor, err = ds.AddStaticFields(i.structs[m.StructName].Size, fields)
		if err != nil {
			return fmt.Errorf("adding fields for datasource: %w", err)
		}
		m.ds = ds
	}
	for _, p := range i.params {
		gadgetCtx.RegisterParam(p)
	}
	return nil
}

func (i *ebpfInstance) Name() string {
	return "ebpfInstance"
}

func (i *ebpfInstance) Prepare(gadgetCtx operators.GadgetContext) error {
	// Create network tracers, one for each socket filter program
	for _, p := range i.collectionSpec.Programs {
		switch p.Type {
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
	return nil
}

func (i *ebpfInstance) Start(gadgetCtx operators.GadgetContext) error {
	i.logger.Debugf("starting")

	gadgets.FixBpfKtimeGetBootNs(i.collectionSpec.Programs)

	mapReplacements := make(map[string]*ebpf.Map)
	for _, v := range i.vars {
		res, _ := gadgetCtx.GetVar(v.name)
		gadgetCtx.Logger().Debugf("got var %q: %+v", v.name, res)
		if m, ok := res.(*ebpf.Map); ok && m != nil {
			i.logger.Debugf("replacing map %q", v.name)
			mapReplacements[v.name] = m
			continue
		}
	}

	i.logger.Debugf("creating ebpf collection")
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	// check if the btfgen operator has stored the kernel types in the context
	if btfSpecI, ok := gadgetCtx.GetVar("kernelTypes"); ok {
		gadgetCtx.Logger().Debugf("using kernel types from BTFHub")
		btfSpec, ok := btfSpecI.(*btf.Spec)
		if !ok {
			return fmt.Errorf("invalid BTF spec")
		}
		opts.Programs.KernelTypes = btfSpec
	}
	collection, err := ebpf.NewCollectionWithOptions(i.collectionSpec, opts)
	if err != nil {
		return fmt.Errorf("creating eBPF collection: %w", err)
	}
	i.collection = collection

	for _, tracer := range i.tracers {
		i.logger.Debugf("starting tracer %q", tracer.MapName)
		go func(tracer *Tracer) {
			err := i.runTracer(gadgetCtx.Context(), tracer)
			if err != nil {
				i.logger.Errorf("starting tracer: %w", err)
			}
		}(tracer)
	}

	// Attach programs
	for progName, p := range i.collectionSpec.Programs {
		l, err := i.attachProgram(gadgetCtx, p, i.collection.Programs[progName])
		if err != nil {
			return fmt.Errorf("attaching eBPF program %q: %w", progName, err)
		}
		if l != nil {
			i.links = append(i.links, l)
		}

		// we need to store links to iterators on a separated list because we need them to run the programs.
		if p.Type == ebpf.Tracing && strings.HasPrefix(p.SectionName, iterPrefix) {
			lIter, ok := l.(*link.Iter)
			if !ok {
				return fmt.Errorf("link is not an iterator")
			}
			i.linksSnapshotters = append(i.linksSnapshotters, &linkSnapshotter{link: lIter, typ: p.AttachTo})
		}
	}

	err = i.runSnapshotters()
	if err != nil {
		return fmt.Errorf("running snapshotters: %w", err)
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

	// Only attach to containers if ifaceName is not set
	if i.ifaceName == "" {
		for _, handler := range i.tcHandlers {
			if err := handler.AttachContainer(container); err != nil {
				return err
			}
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

	if i.ifaceName == "" {
		for _, handler := range i.tcHandlers {
			if err := handler.DetachContainer(container); err != nil {
				return err
			}
		}
	}

	return nil
}

func init() {
	operators.RegisterOperatorForMediaType(eBPFObjectMediaType, &ebpfOperator{})
}
