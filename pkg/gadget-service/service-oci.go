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

package gadgetservice

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func (s *Service) initOperators() error {
	for op, globalParams := range s.operators {
		err := op.Init(globalParams)
		if err != nil {
			return fmt.Errorf("initializing operator %s: %w", op.Name(), err)
		}
	}
	return nil
}

func (s *Service) GetOperatorMap() map[operators.DataOperator]*params.Params {
	return s.operators
}

func (s *Service) GetGadgetInfo(ctx context.Context, req *api.GetGadgetInfoRequest) (*api.GetGadgetInfoResponse, error) {
	if req.Version != api.VersionGadgetInfo {
		return nil, fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetInfo, req.Version)
	}

	if id, ok := strings.CutPrefix(req.ImageName, "attach://"); ok {
		gi := s.instanceMgr.LookupInstance(id)
		if gi == nil {
			return nil, fmt.Errorf("instance %s not found", id)
		}
		gadgetInfo, err := gi.GadgetInfo()
		if err != nil {
			return nil, err
		}
		return &api.GetGadgetInfoResponse{GadgetInfo: gadgetInfo}, nil
	}

	// Get all available operators
	ops := make([]operators.DataOperator, 0)
	for op := range s.operators {
		ops = append(ops, op)
	}

	gadgetCtx := gadgetcontext.New(ctx, req.ImageName, gadgetcontext.WithDataOperators(ops...))

	gi, err := s.runtime.GetGadgetInfo(gadgetCtx, s.runtime.ParamDescs().ToParams(), req.ParamValues)
	if err != nil {
		return nil, fmt.Errorf("getting gadget info: %w", err)
	}
	return &api.GetGadgetInfoResponse{GadgetInfo: gi}, nil
}

func (s *Service) RunGadget(runGadget api.GadgetManager_RunGadgetServer) error {
	ctrl, err := runGadget.Recv()
	if err != nil {
		return err
	}

	attachRequest := ctrl.GetAttachRequest()
	if attachRequest != nil {
		return s.instanceMgr.AttachToGadgetInstance(attachRequest.Id, runGadget)
	}

	ociRequest := ctrl.GetRunRequest()
	if ociRequest == nil {
		return fmt.Errorf("expected first control message to be gadget run request")
	}

	if ociRequest.Version != api.VersionGadgetRunProtocol {
		return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, ociRequest.Version)
	}

	// Create a new logger that logs to gRPC and falls back to the standard logger when it failed to send the message
	logger := logger.NewFromGenericLogger(&Logger{
		send:           runGadget.Send,
		level:          logger.Level(ociRequest.LogLevel),
		fallbackLogger: s.logger,
	})

	for k, v := range ociRequest.ParamValues {
		logger.Debugf("param %s: %s", k, v)
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
			outputBuffer := make(chan *api.GadgetEvent, s.eventBufferLength)

			log := gadgetCtx.Logger()

			go func() {
				// Receive control messages
				for {
					msg, err := runGadget.Recv()
					if err != nil {
						s.logger.Warnf("error on connection: %v", err)
						gadgetCtx.Cancel()
						return
					}
					switch msg.Event.(type) {
					case *api.GadgetControlRequest_StopRequest:
						log.Debugf("received stop request")
						gadgetCtx.Cancel()
						return
					default:
						s.logger.Warn("received unexpected request")
					}
				}
			}()

			go func() {
				// Message pump to handle slow readers
				for {
					select {
					case ev := <-outputBuffer:
						runGadget.Send(ev)
					case <-done:
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

			for _, ds := range gadgetCtx.GetDataSources() {
				dsID := dsLookup[ds.Name()]
				ds.SubscribePacket(func(ds datasource.DataSource, packet datasource.Packet) error {
					d, _ := proto.Marshal(packet.Raw())

					event := &api.GadgetEvent{
						Type:         api.EventTypeGadgetPayload,
						Payload:      d,
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

			// Send gadget information
			d, _ := proto.Marshal(gi)
			err = runGadget.Send(&api.GadgetEvent{
				Type:    api.EventTypeGadgetInfo,
				Payload: d,
			})
			if err != nil {
				s.logger.Warnf("sending gadgetInfo: %v", err)
			}
			s.logger.Debugf("sent gadget info")

			return nil
		}),
	)

	ops := make([]operators.DataOperator, 0)
	for op := range s.operators {
		ops = append(ops, op)
	}
	ops = append(ops, svc)

	gadgetCtx := gadgetcontext.New(
		runGadget.Context(),
		ociRequest.ImageName,
		gadgetcontext.WithLogger(logger),
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithTimeout(time.Duration(ociRequest.Timeout)),
	)

	runtimeParams := s.runtime.ParamDescs().ToParams()
	runtimeParams.CopyFromMap(ociRequest.ParamValues, "runtime.")

	err = s.runtime.RunGadget(gadgetCtx, runtimeParams, ociRequest.ParamValues)
	if err != nil {
		return err
	}
	return nil
}
