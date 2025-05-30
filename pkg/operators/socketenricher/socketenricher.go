// Copyright 2023-2024 The Inspektor Gadget authors
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

// Package socketenricher creates an eBPF map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and display it directly
// from the BPF code. Example of such code in the dns and sni gadgets.
package socketenricher

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracer "github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
)

const (
	OperatorName = "SocketEnricher"
	BTFSpecKey   = "socketEnricherbtf"
	BTFStructKey = "socketEnricherStruct"
	fieldsParam  = "se-fields"
)

type SocketEnricherInterface interface {
	SetSocketEnricherMap(*ebpf.Map)
}

type SocketEnricher struct {
	mu             sync.Mutex
	socketEnricher *tracer.SocketEnricher
	refCount       int
	seConfig       *tracer.Config
}

func (s *SocketEnricher) Name() string {
	return OperatorName
}

func (s *SocketEnricher) Description() string {
	return "Socket enricher provides process information for sockets"
}

func (s *SocketEnricher) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (s *SocketEnricher) ParamDescs() params.ParamDescs {
	return nil
}

func (s *SocketEnricher) Dependencies() []string {
	return nil
}

func (s *SocketEnricher) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}

	instance, err := gi.NewInstance()
	if err != nil {
		log.Warnf("failed to create dummy %s instance: %s", OperatorName, err)
		return false
	}

	_, hasSocketEnricherInterface := instance.(SocketEnricherInterface)
	return hasSocketEnricherInterface
}

func (s *SocketEnricher) Init(params *params.Params) error {
	fields := params.Get(fieldsParam).AsStringSlice()

	s.seConfig = &tracer.Config{}

	for _, field := range fields {
		sizeStr := "512"

		parts := strings.Split(field, "=")
		field := parts[0]
		if len(parts) >= 2 {
			sizeStr = parts[1]
		}

		size, err := strconv.ParseUint(sizeStr, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid size for field %s: %w", field, err)
		}

		switch field {
		case "cwd":
			s.seConfig.Cwd.Enabled = true
			s.seConfig.Cwd.Size = uint32(size)
		case "exepath":
			s.seConfig.Exepath.Enabled = true
			s.seConfig.Exepath.Size = uint32(size)
		default:
			return fmt.Errorf("unsupported field: %s", field)
		}
	}

	return nil
}

func (s *SocketEnricher) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.socketEnricher != nil {
		s.socketEnricher.Close()
		s.socketEnricher = nil
	}
	return nil
}

func (s *SocketEnricher) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	return &SocketEnricherInstance{
		gadgetCtx:      gadgetCtx,
		manager:        s,
		gadgetInstance: gadgetInstance,
	}, nil
}

type SocketEnricherInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *SocketEnricher
	gadgetInstance any
}

func (i *SocketEnricherInstance) Name() string {
	return "SocketEnricherInstance"
}

func (i *SocketEnricherInstance) PreGadgetRun() error {
	setter, ok := i.gadgetInstance.(SocketEnricherInterface)
	if !ok {
		return fmt.Errorf("gadget doesn't implement socket enricher interface")
	}

	i.manager.mu.Lock()
	defer i.manager.mu.Unlock()

	if i.manager.refCount == 0 {
		t, err := tracer.NewSocketEnricher(*i.manager.seConfig)
		if err != nil {
			return err
		}
		i.manager.socketEnricher = t
	}

	i.manager.refCount++

	setter.SetSocketEnricherMap(i.manager.socketEnricher.SocketsMap())

	return nil
}

func (i *SocketEnricherInstance) PostGadgetRun() error {
	i.manager.mu.Lock()
	defer i.manager.mu.Unlock()

	i.manager.refCount--
	if i.manager.refCount == 0 {
		i.manager.socketEnricher.Close()
		i.manager.socketEnricher = nil
	}

	return nil
}

func (i *SocketEnricherInstance) EnrichEvent(ev any) error {
	return nil
}

func (s *SocketEnricher) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          fieldsParam,
			Title:        "Socket enricher fields",
			Description:  "List of fields and their sizes to the enabled on the socket enricher. It uses the field0=size,field1=size,... format",
			DefaultValue: "cwd=512,exepath=512",
			TypeHint:     api.TypeStringSlice,
		},
	}
}

func (s *SocketEnricher) InstanceParams() api.Params {
	return nil
}

func (s *SocketEnricher) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if _, ok := gadgetCtx.GetVar(tracer.SocketsMapName); !ok {
		return nil, nil
	}

	instance := &SocketEnricherInstance{
		gadgetCtx: gadgetCtx,
		manager:   s,
	}
	instance.gadgetInstance = instance
	return instance, nil
}

func (s *SocketEnricher) Priority() int {
	return 10
}

func (i *SocketEnricherInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	err := i.PreGadgetRun()
	if err != nil {
		return err
	}

	types, btfStruct, err := i.manager.socketEnricher.Types()
	if err != nil {
		return err
	}

	gadgetCtx.SetVar(BTFSpecKey, types)
	gadgetCtx.SetVar(BTFStructKey, btfStruct)
	return nil
}

func (i *SocketEnricherInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (i *SocketEnricherInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return i.PostGadgetRun()
}

func (i *SocketEnricherInstance) SetSocketEnricherMap(m *ebpf.Map) {
	i.gadgetCtx.Logger().Debugf("setting sockets map")
	i.gadgetCtx.SetVar(tracer.SocketsMapName, m)
}

func init() {
	op := &SocketEnricher{}
	operators.Register(op)
	operators.RegisterDataOperator(op)
}
