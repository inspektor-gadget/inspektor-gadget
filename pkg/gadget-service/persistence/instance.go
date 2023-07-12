// Copyright 2023 The Inspektor Gadget authors
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

package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type gadgetState int

const (
	stateRunning = iota
	statePaused
	stateError
)

type PersistentGadgetClient struct {
	client api.GadgetManager_AttachToPersistentGadgetServer
	buffer chan *api.GadgetEvent
	seq    uint32
}

func NewPersistentGadgetClient(client api.GadgetManager_AttachToPersistentGadgetServer) *PersistentGadgetClient {
	c := &PersistentGadgetClient{
		client: client,
		buffer: make(chan *api.GadgetEvent, 1024),
		seq:    0,
	}
	return c
}

func (c *PersistentGadgetClient) Run() {
	done := c.client.Context().Done()
	for {
		select {
		case buf := <-c.buffer:
			c.client.Send(buf)
		case <-done:
			log.Debug("client done")
			return
		}
	}
	// TODO: remove from trace
}

func (c *PersistentGadgetClient) SendPayload(payload []byte) {
	c.seq++
	event := &api.GadgetEvent{
		Type:    api.EventTypeGadgetPayload,
		Payload: payload,
		Seq:     c.seq,
	}
	select {
	case c.buffer <- event:
	default:
	}
}

type PersistentGadgetInstance struct {
	request         *api.GadgetRunRequest
	mu              sync.Mutex
	eventBuffer     [][]byte
	eventBufferOffs int
	eventOverflow   bool
	results         runtime.CombinedGadgetResult
	gadgetCtx       *gadgetcontext.GadgetContext
	clients         map[*PersistentGadgetClient]struct{}
	cancel          func()
	state           gadgetState
	error           error
}

func (p *PersistentGadgetInstance) AddClient(client api.GadgetManager_AttachToPersistentGadgetServer) {
	log.Debugf("adding client")
	p.mu.Lock()
	defer p.mu.Unlock()
	cl := NewPersistentGadgetClient(client)
	p.clients[cl] = struct{}{}
	// TODO: Replay
	go func() {
		cl.Run()
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.clients, cl)
	}()
}

func (p *PersistentGadgetInstance) RunGadget(
	ctx context.Context,
	runtime runtime.Runtime,
	logger logger.Logger,
	request *api.GadgetRunRequest,
) error {
	gadgetDesc := gadgetregistry.Get(request.GadgetCategory, request.GadgetName)
	if gadgetDesc == nil {
		return fmt.Errorf("gadget not found: %s/%s", request.GadgetCategory, request.GadgetName)
	}

	// Initialize Operators
	err := operators.GetAll().Init(operators.GlobalParamsCollection())
	if err != nil {
		return fmt.Errorf("initialize operators: %w", err)
	}

	ops := operators.GetOperatorsForGadget(gadgetDesc)

	operatorParams := ops.ParamCollection()
	err = operatorParams.CopyFromMap(request.Params, "operator.")
	if err != nil {
		return fmt.Errorf("setting operator parameters: %w", err)
	}

	parser := gadgetDesc.Parser()

	runtimeParams := runtime.ParamDescs().ToParams()
	err = runtimeParams.CopyFromMap(request.Params, "runtime.")
	if err != nil {
		return fmt.Errorf("setting runtime parameters: %w", err)
	}

	gadgetParamDescs := gadgetDesc.ParamDescs()
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()
	err = gadgetParams.CopyFromMap(request.Params, "")
	if err != nil {
		return fmt.Errorf("setting gadget parameters: %w", err)
	}

	if c, ok := gadgetDesc.(gadgets.GadgetDescCustomParser); ok {
		var err error
		parser, err = c.CustomParser(gadgetParams, request.Args)
		if err != nil {
			return fmt.Errorf("calling custom parser: %w", err)
		}
	}

	if parser != nil {
		outputDone := make(chan bool)
		defer func() {
			outputDone <- true
		}()

		parser.SetLogCallback(logger.Logf)
		parser.SetEventCallback(func(ev any) {
			data, _ := json.Marshal(ev)

			p.mu.Lock()
			p.eventBuffer[p.eventBufferOffs] = data
			p.eventBufferOffs = (p.eventBufferOffs + 1) % len(p.eventBuffer)
			if p.eventBufferOffs == 0 {
				p.eventOverflow = true
			}
			for client := range p.clients {
				// This doesn't block
				client.SendPayload(data)
			}
			p.mu.Unlock()
		})
	}

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		ctx,
		runID,
		runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		request.Args,
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
	)
	defer gadgetCtx.Cancel()

	p.gadgetCtx = gadgetCtx

	// Hand over to runtime
	results, err := runtime.RunGadget(gadgetCtx)
	if err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	// Send result, if any
	p.mu.Lock()
	p.results = results
	p.state = statePaused
	p.mu.Unlock()

	return nil
}
