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
	stateInvalid gadgetState = iota
	stateRunning
	stateError
)

type bufferedEvent struct {
	datasourceID uint32
	payload      []byte
}

type GadgetInstance struct {
	id                   string
	name                 string
	mgr                  *Manager
	request              *api.GadgetRunRequest
	mu                   sync.Mutex
	gadgetInfoSerialized *api.GadgetEvent
	gadgetInfo           *api.GadgetInfo
	eventBuffer          []*bufferedEvent
	eventBufferOffs      int
	eventOverflow        bool
	clients              map[*GadgetInstanceClient]struct{}
	cancel               func()
	state                gadgetState
	error                error
	ready                chan struct{}
}

func (p *GadgetInstance) GadgetInfo() (*api.GadgetInfo, error) {
	<-p.ready
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gadgetInfo, p.error
}

func (p *GadgetInstance) AddClient(client api.GadgetManager_RunGadgetServer) chan struct{} {
	log.Debugf("[%s] client connected", p.gadgetInfo.Id)
	p.mu.Lock()
	cl := NewGadgetInstanceClient(client)
	p.clients[cl] = struct{}{}
	var replayBuf []*bufferedEvent
	if p.eventOverflow {
		replayBuf = make([]*bufferedEvent, 0, len(p.eventBuffer))
		replayBuf = append(replayBuf, p.eventBuffer[p.eventBufferOffs:]...)
		replayBuf = append(replayBuf, p.eventBuffer[:p.eventBufferOffs]...)
	} else {
		replayBuf = make([]*bufferedEvent, 0, p.eventBufferOffs)
		replayBuf = append(replayBuf, p.eventBuffer[:p.eventBufferOffs]...)
	}
	log.Debugf("replaying %d entries (%d)", len(replayBuf), p.eventBufferOffs)
	cl.replayBuf = replayBuf

	// Set next seq to match the first entry _after_ the replay; the replay will use the seq numbers up to that
	cl.seq = uint32(len(replayBuf))
	p.mu.Unlock()

	done := make(chan struct{})
	err := client.Send(p.gadgetInfoSerialized)
	if err != nil {
		p.mu.Lock()
		delete(p.clients, cl)
		p.mu.Unlock()
		log.Debugf("[%s] client disconnected (failed to send gadget info): %c", p.gadgetInfo.Id, err)
		close(done)
		return done
	}

	go func() {
		err := cl.Run()
		if err != nil {
			log.Debugf("[%s] client disconnected (with error): %v", p.gadgetInfo.Id, err)
		} else {
			log.Debugf("[%s] client disconnected", p.gadgetInfo.Id)
		}
		p.mu.Lock()
		delete(p.clients, cl)
		p.mu.Unlock()
		close(done)
	}()
	return done
}

func (p *GadgetInstance) RemoveClients() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for client := range p.clients {
		client.Close()
	}
}

func (p *GadgetInstance) Run(
	ctx context.Context,
	runtime runtime.Runtime,
	logger logger.Logger,
) error {
	if p.request.Version != api.VersionGadgetRunProtocol {
		return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, p.request.Version)
	}

	// Build a simple operator that subscribes to all events and forwards them
	svc := simple.New("svc",
		simple.WithPriority(50000),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			gi, err := gadgetCtx.SerializeGadgetInfo()
			if err != nil {
				return fmt.Errorf("serializing gadget info: %w", err)
			}

			// datasource mapping; we're sending an array of available DataSources including a
			// DataSourceID; this ID will be used when sending actual data and needs to be remapped
			// to the actual DataSource on the client later on
			dsLookup := make(map[string]uint32, len(gi.DataSources))
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

					p.mu.Lock()
					p.eventBuffer[p.eventBufferOffs] = event
					p.eventBufferOffs = (p.eventBufferOffs + 1) % len(p.eventBuffer)
					if p.eventBufferOffs == 0 {
						p.eventOverflow = true
					}
					for client := range p.clients {
						// This doesn't block
						client.SendPayload(dsID, d)
					}
					p.mu.Unlock()
					return nil
				}, 1000000) // TODO: static int?
			}

			// add ID and name as reference; this is used later on by the client to address this gadget run
			gi.Id = p.id
			gi.Name = p.name

			d, _ := proto.Marshal(gi)
			p.gadgetInfoSerialized = &api.GadgetEvent{
				Type:    api.EventTypeGadgetInfo,
				Payload: d,
			}
			p.gadgetInfo = gi
			close(p.ready)
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
		p.request.ImageName,
		gadgetcontext.WithLogger(logger),
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithAsRemoteCall(true),
		gadgetcontext.WithName(p.name),
		gadgetcontext.WithID(p.id),
	)

	runtimeParams := runtime.ParamDescs().ToParams()
	runtimeParams.CopyFromMap(p.request.ParamValues, "runtime.")

	return runtime.RunGadget(gadgetCtx, runtimeParams, p.request.ParamValues)
}
