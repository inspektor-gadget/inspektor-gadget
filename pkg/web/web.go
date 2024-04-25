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

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	dsjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type WebSocketServer struct {
	runtime runtime.Runtime
}

func NewWebServer(runtime runtime.Runtime) *WebSocketServer {
	return &WebSocketServer{
		runtime: runtime,
	}
}

type sConn struct {
	*websocket.Conn
	srv        *WebSocketServer
	runtime    runtime.Runtime
	gadgets    map[string]*gadgetcontext.GadgetContext
	gadgetLock sync.Mutex
	connLock   sync.Mutex
	encoder    *json.Encoder
}

func (c *sConn) handle() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		command := &Command{}
		err := c.Conn.ReadJSON(command)
		if err != nil {
			log.Warnf("reading JSON: %v", err)
			return
		}
		switch command.Action {
		case "info":
			var imageName string
			json.Unmarshal(command.Payload, &imageName)

			ops := make([]operators.DataOperator, 0)
			for _, op := range operators.GetDataOperators() {
				ops = append(ops, op)
			}
			ops = append(ops, ocihandler.OciHandler)

			gadgetCtx := gadgetcontext.New(ctx, imageName, gadgetcontext.WithDataOperators(ops...))
			info, err := c.runtime.GetGadgetInfo(gadgetCtx, c.runtime.ParamDescs().ToParams(), nil)
			if err != nil {
				log.Warnf("getting gadget info: %v", err)
				continue
			}
			d, _ := protojson.Marshal(info)
			ev := &GadgetEvent{ID: command.ID, Payload: d}
			c.WriteJSON(ev)
		// case "list":
		// 	res, err := c.srv.persistenceMgr.ListPersistentGadgets(ctx, &api.ListPersistentGadgetRequest{})
		// 	if err != nil {
		// 		c.WriteError(command, err)
		// 		continue
		// 	}
		// 	d, _ := protojson.Marshal(res)
		// 	ev := &GadgetEvent{ID: command.ID, Payload: d}
		// 	c.WriteJSON(ev)
		// case "delete":
		// 	id := &ID{}
		// 	if err := json.Unmarshal(command.Payload, &id); err != nil {
		// 		c.WriteError(command, err)
		// 		continue
		// 	}
		// 	res, err := c.srv.persistenceMgr.RemovePersistentGadget(ctx, &api.PersistentGadgetId{Id: id.ID})
		// 	if err != nil {
		// 		c.WriteError(command, err)
		// 		continue
		// 	}
		// 	d, _ := protojson.Marshal(res)
		// 	ev := &GadgetEvent{ID: command.ID, Payload: d}
		// 	c.WriteJSON(ev)
		case "start":
			// Create a new gadget
			gadgetStartRequest := &GadgetStartRequest{}
			if err := json.Unmarshal(command.Payload, &gadgetStartRequest); err != nil {
				c.WriteError(command, err)
				continue
			}
			err := c.startGadget(ctx, gadgetStartRequest)
			if err != nil {
				log.Warnf("error from gadget: %v", err)
			}
		case "stop":
			gadgetStopRequest := &GadgetStopRequest{}
			if err := json.Unmarshal(command.Payload, &gadgetStopRequest); err != nil {
				c.WriteError(command, err)
				continue
			}
			err := c.stopGadget(gadgetStopRequest.ID)
			if err != nil {
				c.WriteError(command, err)
			}
		}
	}
}

func (c *sConn) stopGadget(id string) error {
	c.gadgetLock.Lock()
	defer c.gadgetLock.Unlock()

	if gadget, ok := c.gadgets[id]; ok {
		log.Warnf("stopping gadget %s", id)
		gadget.Cancel()
		delete(c.gadgets, id)
	}
	return nil
}

func (c *sConn) WriteError(cmd *Command, err error) error {
	p, _ := json.Marshal(err.Error())
	return c.Conn.WriteJSON(&GadgetEvent{ID: cmd.ID, Type: 255, Payload: p})
}

func (c *sConn) WriteJSON(payload any) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	return c.Conn.WriteJSON(payload)
}

func (c *sConn) startGadget(ctx context.Context, request *GadgetStartRequest) error {
	c.gadgetLock.Lock()
	defer c.gadgetLock.Unlock()

	if _, ok := c.gadgets[request.ID]; ok {
		return fmt.Errorf("gadget with ID %q already exists", request.ID)
	}

	logger := logger.NewFromGenericLogger(&Logger{
		send: func(event *GadgetEvent) error {
			event.ID = request.ID
			err := c.WriteJSON(event)
			if err != nil {
				// TODO: Shutdown
				log.Warnf("writing JSON: %v", err)
			}
			return nil
		},
		level: logger.Level(request.LogLevel),
		// fallbackLogger: s.logger, // TODO
	})

	// Build a simple operator that subscribes to all events and forwards them
	svc := simple.New("svc",
		simple.WithPriority(50000),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Create payload buffer
			outputBuffer := make(chan *GadgetEvent, 1024) // TODO

			go func() {
				// Message pump to handle slow readers
				for {
					select {
					case ev := <-outputBuffer:
						err := c.WriteJSON(ev)
						if err != nil {
							log.Warnf("writing gadget event: %v (%s)", err, string(ev.Payload))
						}
					case <-ctx.Done():
						return
					}
				}
			}()

			seq := uint32(0)
			var seqLock sync.Mutex

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

			// Send gadget information
			d, _ := protojson.Marshal(gi)
			err = c.WriteJSON(&GadgetEvent{
				Type:    api.EventTypeGadgetInfo,
				Payload: d,
			})
			if err != nil {
				log.Warnf("sending gadgetInfo: %v", err)
			}
			log.Debugf("sent gadget info")

			for _, ds := range gadgetCtx.GetDataSources() {
				dsID := dsLookup[ds.Name()]
				jsonEnc, _ := dsjson.New(ds, dsjson.WithAsArray(true))

				d, _ := json.Marshal(jsonEnc.FieldNames())
				err = c.WriteJSON(&GadgetEvent{
					Type:         1000,
					Payload:      d,
					DataSourceID: dsID,
				})
				if err != nil {
					log.Warnf("sending fieldnames: %v", err)
				}

				ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
					d := jsonEnc.Marshal(data)
					pl := make([]byte, len(d))
					copy(pl, d) // TODO: optimize
					// err = c.WriteJSON(&GadgetEvent{
					// 	Type:    api.EventTypeGadgetInfo,
					// 	Payload: d,
					// })

					event := &GadgetEvent{
						Type:         api.EventTypeGadgetPayload,
						Payload:      pl,
						DataSourceID: dsID,
					}

					seqLock.Lock()
					seq++
					event.Seq = seq

					// Try to send event; if outputBuffer is full, it will be dropped by taking
					// the default path.
					select {
					case outputBuffer <- event:
					default:
					}
					seqLock.Unlock()
					return nil
				}, 1000000) // TODO: static int?
			}

			return nil
		}),
	)

	// Build a gadget context and wire everything up

	ops := make([]operators.DataOperator, 0)
	for _, op := range operators.GetDataOperators() {
		ops = append(ops, op)
	}
	ops = append(ops, ocihandler.OciHandler, svc)

	gadgetCtx := gadgetcontext.New(
		ctx,
		request.ImageName,
		gadgetcontext.WithLogger(logger),
		gadgetcontext.WithDataOperators(ops...),
	)

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()
	if runID == "" {
		// TODO REMOVE
	}

	c.gadgets[request.ID] = gadgetCtx

	log.Warnf("started gadget %s %q", request.ID, request.ImageName)

	go func() {
		defer gadgetCtx.Cancel()
		defer func() {
			c.gadgetLock.Lock()
			defer c.gadgetLock.Unlock()

			delete(c.gadgets, request.ID)
		}()

		// Hand over to runtime
		err := c.runtime.RunGadget(gadgetCtx, nil, request.ParamValues)
		if err != nil {
			log.Warnf("error from gadget: %v", err)
			// return fmt.Errorf("running gadget: %w", err)
		}
	}()

	return nil
}

func (s *WebSocketServer) Run(network, addr string) error {
	srv := http.NewServeMux()
	srv.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade:", err)
			return
		}
		defer c.Close()
		(&sConn{
			Conn:    c,
			srv:     s,
			runtime: s.runtime,
			gadgets: map[string]*gadgetcontext.GadgetContext{},
		}).handle()
	})
	log.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, srv)
}
