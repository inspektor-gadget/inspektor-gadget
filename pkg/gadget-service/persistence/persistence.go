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
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Store interface {
	InstallPersistentGadget(ctx context.Context, req *api.InstallPersistentGadgetRequest) (*api.InstallPersistentGadgetResponse, error)
	ListPersistentGadgets(context.Context, *api.ListPersistentGadgetRequest) (*api.ListPersistentGadgetResponse, error)
	RemovePersistentGadget(context.Context, *api.PersistentGadgetId) (*api.StatusResponse, error)
	StopPersistentGadget(context.Context, *api.PersistentGadgetId) (*api.StatusResponse, error)
	GetPersistentGadget(ctx context.Context, req *api.PersistentGadgetId) (*api.PersistentGadget, error)
}

// Manager manages running gadgets without connection based context. It can run gadgets in the background as
// well as buffer and multiplex their output.
type Manager struct {
	// mu is to be used whenever a gadget is installed or a new client wants to attach to a gadget
	mu              sync.Mutex
	gadgetInstances map[string]*PersistentGadgetInstance
	waitingRoom     sync.Map

	// asyncGadgetRunCreation tells the Manager whether it is completely in control of creating gadget
	// runs, or if those are (also) externally managed, like through custom resources in a kubernetes environment
	asyncGadgetRunCreation bool

	runtime runtime.Runtime
	store   Store
}

func NewManager(runtime runtime.Runtime, async bool) *Manager {
	mgr := &Manager{
		gadgetInstances:        make(map[string]*PersistentGadgetInstance),
		runtime:                runtime,
		asyncGadgetRunCreation: async,
	}
	return mgr
}

func (p *Manager) SetStore(store Store) {
	p.store = store
}

func (p *Manager) InstallPersistentGadget(ctx context.Context, req *api.InstallPersistentGadgetRequest) (*api.InstallPersistentGadgetResponse, error) {
	return p.store.InstallPersistentGadget(ctx, req)
}

func (p *Manager) ListPersistentGadgets(ctx context.Context, request *api.ListPersistentGadgetRequest) (*api.ListPersistentGadgetResponse, error) {
	return p.store.ListPersistentGadgets(ctx, request)
}

func (p *Manager) RemovePersistentGadget(ctx context.Context, request *api.PersistentGadgetId) (*api.StatusResponse, error) {
	return p.store.RemovePersistentGadget(ctx, request)
}

func (p *Manager) StopPersistentGadget(ctx context.Context, request *api.PersistentGadgetId) (*api.StatusResponse, error) {
	return p.store.StopPersistentGadget(ctx, request)
}

func (p *Manager) GetPersistentGadget(ctx context.Context, req *api.PersistentGadgetId) (*api.PersistentGadget, error) {
	return p.store.GetPersistentGadget(ctx, req)
}

func (p *Manager) AttachToPersistentGadget(req *api.PersistentGadgetId, client api.GadgetManager_AttachToPersistentGadgetServer) error {
	log.Debugf("new client")

	p.mu.Lock()
	// First, check whether we know about the gadget (already); in case a gadget run is created using a custom resource
	// in the kubernetes world, a client might want to attach before we know about the gadget run ourselves.
	gadgetInstance, found := p.gadgetInstances[req.Id]
	if !found && !p.asyncGadgetRunCreation {
		return fmt.Errorf("not found")
	}
	if !found {
		// Place into waitingRoom
		p.waitingRoom.Store(client, req.Id)
	} else {
		gadgetInstance.AddClient(client)
	}
	p.mu.Unlock()

	// wait for client to be done
	<-client.Context().Done()

	// TODO: remove from waiting room or gadgetInstance
	return nil
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
	id string,
	request *api.GadgetRunRequest,
) {
	ctx, cancel := context.WithCancel(context.Background())
	pg := &PersistentGadgetInstance{
		request:         request,
		eventBuffer:     make([][]byte, 1024),
		eventBufferOffs: 0,
		cancel:          cancel,
		clients:         map[*PersistentGadgetClient]struct{}{},
	}
	p.mu.Lock()
	p.gadgetInstances[id] = pg
	// Adopt all clients in the waiting room
	if p.asyncGadgetRunCreation {
		p.waitingRoom.Range(func(key, value any) bool {
			if value.(string) == id {
				log.Debugf("adopting client")
				pg.AddClient(key.(api.GadgetManager_AttachToPersistentGadgetServer))
			}
			p.waitingRoom.Delete(key)
			return true
		})
	}
	p.mu.Unlock()
	go func() {
		defer cancel()
		err := pg.RunGadget(ctx, p.runtime, logger.DefaultLogger(), request)
		if err != nil {
			pg.mu.Lock()
			pg.state = stateError
			pg.error = err
			pg.mu.Unlock()
		}
	}()
}
