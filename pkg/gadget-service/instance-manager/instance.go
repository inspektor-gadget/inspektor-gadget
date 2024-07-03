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

package instancemanager

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type gadgetState int

const (
	stateRunning = iota
	statePaused
	stateError
)

type bufferedEvent struct {
	datasourceID uint32
	payload      []byte
}

type GadgetInstance struct {
	id              string
	name            string
	mgr             *Manager
	request         *api.GadgetRunRequest
	mu              sync.Mutex
	gadgetInfo      *api.GadgetEvent
	gadgetInfoRaw   *api.GadgetInfo
	eventBuffer     []*bufferedEvent
	eventBufferOffs int
	eventOverflow   bool
	results         runtime.CombinedGadgetResult
	gadgetCtx       *gadgetcontext.GadgetContext
	clients         map[*GadgetInstanceClient]struct{}
	cancel          func()
	state           gadgetState
	error           error
}

func (p *GadgetInstance) GadgetInfo() (*api.GadgetInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gadgetInfoRaw, p.error
}

func (p *GadgetInstance) AddClient(client api.GadgetManager_AttachToGadgetInstanceServer) {
	log.Debugf("[%s] client connected", p.gadgetInfoRaw.Id)
	p.mu.Lock()
	defer p.mu.Unlock()
	cl := NewGadgetInstanceClient(client)
	p.clients[cl] = struct{}{}
	client.Send(p.gadgetInfo)
	// TODO: Replay
	go func() {
		cl.Run()
		log.Debugf("[%s] client disconnected", p.gadgetInfoRaw.Id)
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.clients, cl)
	}()
}

func (p *GadgetInstance) RunGadget(
	ctx context.Context,
	runtime runtime.Runtime,
	logger logger.Logger,
	request *api.GadgetRunRequest,
) error {
	if request.Version != api.VersionGadgetRunProtocol {
		return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, request.Version)
	}

	done := make(chan bool)
	defer func() {
		done <- true
	}()

	// Build a simple operator that subscribes to all events and forwards them
	svc := simple.New("svc",
		simple.WithPriority(50000),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Create payload buffer
			// go func() {
			// 	// Receive control messages
			// 	for {
			// 		msg, err := runGadget.Recv()
			// 		if err != nil {
			// 			s.logger.Warnf("error on connection: %v", err)
			// 			gadgetCtx.Cancel()
			// 			return
			// 		}
			// 		switch msg.Event.(type) {
			// 		case *api.GadgetControlRequest_StopRequest:
			// 			log.Debugf("received stop request")
			// 			gadgetCtx.Cancel()
			// 			return
			// 		default:
			// 			logger.Warn("received unexpected request")
			// 		}
			// 	}
			// }()

			gi, err := gadgetCtx.SerializeGadgetInfo()
			if err != nil {
				return fmt.Errorf("serializing gadget info: %w", err)
			}

			// datasource mapping; we're sending an array of available DataSources including a
			// DataSourceID; this ID will be used when sending actual data and needs to be remapped
			// to the actual DataSource on the client later on
			dsLookup := make(map[string]uint32)
			for i, ds := range gi.DataSources {
				ds.Id = uint32(i)
				dsLookup[ds.Name] = ds.Id
			}

			// todo: skip DataSources we're not interested in

			for _, ds := range gadgetCtx.GetDataSources() {
				dsID := dsLookup[ds.Name()]
				ds.SubscribePacket(func(ds datasource.DataSource, data datasource.Packet) error {
					d, _ := proto.Marshal(data.Raw())

					event := &bufferedEvent{
						payload:      d,
						datasourceID: dsID,
					}

					p.eventBuffer[p.eventBufferOffs] = event
					p.eventBufferOffs = (p.eventBufferOffs + 1) % len(p.eventBuffer)
					if p.eventBufferOffs == 0 {
						p.eventOverflow = true
					}
					for client := range p.clients {
						// This doesn't block
						client.SendPayload(dsID, d)
					}
					return nil
				}, 1000000) // TODO: static int?
			}

			// add ID and name as reference; this is used later on by the client to address this gadget run
			gi.Id = p.id
			gi.Name = p.name

			d, _ := proto.Marshal(gi)
			p.gadgetInfo = &api.GadgetEvent{
				Type:    api.EventTypeGadgetInfo,
				Payload: d,
			}
			p.gadgetInfoRaw = gi
			return nil
		}),
	)

	ops := make([]operators.DataOperator, 0)
	for op := range p.mgr.GetOperatorMap() {
		ops = append(ops, op)
	}
	ops = append(ops, svc)

	gadgetCtx := gadgetcontext.New(
		ctx,
		request.ImageName,
		gadgetcontext.WithLogger(logger),
		gadgetcontext.WithDataOperators(ops...),
	)

	runtimeParams := runtime.ParamDescs().ToParams()
	runtimeParams.CopyFromMap(request.ParamValues, "runtime.")

	err := runtime.RunGadget(gadgetCtx, runtimeParams, request.ParamValues)
	if err != nil {
		p.mu.Lock()
		p.error = err
		p.mu.Unlock()
		return err
	}
	return nil
}
