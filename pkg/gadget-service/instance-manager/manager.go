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
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Service interface {
	GetOperatorMap() map[operators.DataOperator]*params.Params
}

// Manager manages running gadgets without connection based context. It can run gadgets in the background as
// well as buffer and multiplex their output.
type Manager struct {
	// api.GadgetInstanceManagerServer

	// mu is to be used whenever a gadget is installed or a new client wants to attach to a gadget
	mu              sync.Mutex
	gadgetInstances map[string]*GadgetInstance
	waitingRoom     sync.Map

	gadgetDone chan bool

	// asyncGadgetRunCreation tells the Manager whether it is completely in control of creating gadget
	// runs, or if those are (also) externally managed, like through custom resources in a kubernetes environment
	asyncGadgetRunCreation bool

	runtime runtime.Runtime
	Store

	Service
}

func New(runtime runtime.Runtime, async bool) *Manager {
	mgr := &Manager{
		gadgetInstances:        make(map[string]*GadgetInstance),
		gadgetDone:             make(chan bool, 1),
		asyncGadgetRunCreation: async,
		runtime:                runtime,
	}
	return mgr
}

func (p *Manager) SetStore(store Store) {
	p.Store = store
}

// StopGadget cancels a running gadget, but leaves the results accessible
func (p *Manager) StopGadget(id string) error {
	log.Printf("stopping gadget %q", id)
	p.mu.Lock()
	defer p.mu.Unlock()

	gadgetInstance, ok := p.gadgetInstances[id]
	if !ok {
		return fmt.Errorf("gadget not found")
	}
	gadgetInstance.cancel()

	// ensure that the gadget is stopped before returning
	if gadgetInstance.state == stateRunning {
		<-p.gadgetDone
	}

	return nil
}

// RemoveGadget cancels and removes a gadget
func (p *Manager) RemoveGadget(id string) error {
	log.Printf("removing gadget %q", id)
	p.mu.Lock()
	defer p.mu.Unlock()

	gadgetInstance, ok := p.gadgetInstances[id]
	if !ok {
		return fmt.Errorf("gadget not found")
	}
	gadgetInstance.cancel()
	delete(p.gadgetInstances, id)
	return nil
}

func (p *Manager) RunGadget(
	instance *api.GadgetInstance,
) {
	ctx, cancel := context.WithCancel(context.Background())
	gi := &GadgetInstance{
		id:              instance.Id,
		name:            instance.Name,
		mgr:             p,
		request:         instance.GadgetInfo,
		eventBuffer:     make([]*bufferedEvent, 1024),
		eventBufferOffs: 0,
		cancel:          cancel,
		clients:         map[*GadgetInstanceClient]struct{}{},
	}
	p.mu.Lock()
	p.gadgetInstances[gi.id] = gi
	// Adopt all clients in the waiting room
	if p.asyncGadgetRunCreation {
		p.waitingRoom.Range(func(key, value any) bool {
			if value.(string) == gi.id {
				log.Debugf("adopting client")
				gi.AddClient(key.(api.GadgetManager_AttachToGadgetInstanceServer))
			}
			p.waitingRoom.Delete(key)
			return true
		})
	}
	p.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			p.gadgetDone <- true
		}()
		err := gi.RunGadget(ctx, p.runtime, logger.DefaultLogger(), gi.request)
		if err != nil {
			log.Errorf("running gadget: %v", err)
			gi.mu.Lock()
			gi.state = stateError
			gi.error = err
			gi.mu.Unlock()
		}
	}()
}

func (p *Manager) LookupInstance(gadgetInstanceID string) *GadgetInstance {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. Match by complete ID
	if gi, ok := p.gadgetInstances[gadgetInstanceID]; ok {
		return gi
	}

	// 2. Match by name
	for _, gi := range p.gadgetInstances {
		if gi.name == gadgetInstanceID {
			return gi
		}
	}

	// 3. Partial match by ID or Name
	for gid, gi := range p.gadgetInstances {
		if strings.HasPrefix(gid, gadgetInstanceID) {
			return gi
		}
		if strings.HasPrefix(gi.name, gadgetInstanceID) {
			return gi
		}
	}

	return nil
}

func (p *Manager) AttachToGadgetInstance(
	gadgetInstanceID string, stream api.GadgetManager_AttachToGadgetInstanceServer,
) error {
	p.mu.Lock()
	gi, ok := p.gadgetInstances[gadgetInstanceID]
	p.mu.Unlock()
	if !ok {
		return fmt.Errorf("gadget %s not found", gadgetInstanceID)
	}

	gi.AddClient(stream)

	<-stream.Context().Done()
	return nil
}
