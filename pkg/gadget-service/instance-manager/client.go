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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type GadgetInstanceClient struct {
	client api.GadgetManager_AttachToGadgetInstanceServer
	buffer chan *api.GadgetEvent
	seq    uint32
}

func NewGadgetInstanceClient(client api.GadgetManager_AttachToGadgetInstanceServer) *GadgetInstanceClient {
	c := &GadgetInstanceClient{
		client: client,
		buffer: make(chan *api.GadgetEvent, 1024),
		seq:    0,
	}
	return c
}

func (c *GadgetInstanceClient) Run() {
	done := c.client.Context().Done()
	for {
		select {
		case buf := <-c.buffer:
			c.client.Send(buf)
		case <-done:
			return
		}
	}
}

func (c *GadgetInstanceClient) SendPayload(datasourceID uint32, payload []byte) {
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
