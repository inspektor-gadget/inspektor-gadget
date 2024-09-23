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
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type GadgetInstanceClient struct {
	mu         sync.Mutex
	client     api.GadgetManager_RunGadgetServer
	buffer     chan *api.GadgetEvent
	seq        uint32
	gadgetDone chan struct{}
	replayBuf  []*bufferedEvent
}

func NewGadgetInstanceClient(client api.GadgetManager_RunGadgetServer) *GadgetInstanceClient {
	c := &GadgetInstanceClient{
		client:     client,
		buffer:     make(chan *api.GadgetEvent, 1024),
		seq:        0,
		gadgetDone: make(chan struct{}),
	}
	return c
}

func (c *GadgetInstanceClient) Close() {
	close(c.gadgetDone)
}

func (c *GadgetInstanceClient) Run() error {
	done := c.client.Context().Done()
	for i, ev := range c.replayBuf {
		err := c.client.Send(&api.GadgetEvent{
			Type:         api.EventTypeGadgetPayload,
			DataSourceID: ev.datasourceID,
			Payload:      ev.payload,
			Seq:          uint32(i) + 1,
		})
		if err != nil {
			return err
		}
	}
	c.replayBuf = nil
	for {
		select {
		case buf := <-c.buffer:
			err := c.client.Send(buf)
			if err != nil {
				return err
			}
		case <-done:
			return nil
		case <-c.gadgetDone:
			return nil
		}
	}
}

func (c *GadgetInstanceClient) SendPayload(datasourceID uint32, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	event := &api.GadgetEvent{
		Type:         api.EventTypeGadgetPayload,
		DataSourceID: datasourceID,
		Payload:      payload,
		Seq:          c.seq,
	}
	select {
	case c.buffer <- event:
	default:
	}
}
