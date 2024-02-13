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
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	ocioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func (s *Service) GetOCIGadgetInfo(ctx context.Context, req *api.GetOCIGadgetInfoRequest) (*api.GetOCIGadgetInfoResponse, error) {
	if req.Version != api.VersionGadgetInfo {
		return nil, fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetInfo, req.Version)
	}

	ociParams := ocioperator.OciHandler.ParamDescs().ToParams()
	ociParams.CopyFromMap(req.Params, "oci.")

	// For this gadgetCtx, we only need ociParams to be able to fetch the image and analyze it
	gadgetCtx := gadgetcontext.NewOCI(ctx, req.ImageName, s.logger, params.Collection{"oci": ociParams})

	for k, p := range gadgetCtx.LocalOperatorsParamCollection() {
		for _, v := range *p {
			s.logger.Debugf("%s / %s: %s", k, v.Key, v.AsString())
		}
	}

	gi, err := s.runtime.GetOCIGadgetInfo(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("getting gadget info: %w", err)
	}
	return &api.GetOCIGadgetInfoResponse{GadgetInfo: gi}, nil
}

func (s *Service) RunOCIGadget(runGadget api.OCIGadgetManager_RunOCIGadgetServer) error {
	ctrl, err := runGadget.Recv()
	if err != nil {
		return err
	}

	ociRequest := ctrl.GetOciRunRequest()
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

	runtime := s.runtime

	for k, v := range ociRequest.Params {
		logger.Debugf("param %s: %s", k, v)
	}

	ociParams := ocioperator.OciHandler.ParamDescs().ToParams()
	ociParams.CopyFromMap(ociRequest.Params, "oci.")

	gadgetCtx := gadgetcontext.NewOCI(runGadget.Context(), ociRequest.ImageName, logger, params.Collection{
		"oci": ociParams,
	}) // TODO

	// Create payload buffer
	outputBuffer := make(chan *api.GadgetEvent, s.eventBufferLength)

	outputDone := make(chan bool)
	defer func() {
		outputDone <- true
	}()

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
			case *api.OCIGadgetControlRequest_StopRequest:
				logger.Debugf("received stop request")
				gadgetCtx.Cancel()
				return
			default:
				logger.Warn("unexpected request")
			}
		}
	}()

	go func() {
		// Message pump to handle slow readers
		for {
			select {
			case ev := <-outputBuffer:
				runGadget.Send(ev)
			case <-outputDone:
				return
			}
		}
	}()

	seq := uint32(0)
	var seqLock sync.Mutex

	// Register OnPrepare callback - this is called once the gadget information and all DataSources
	// are available; in here we subscribe to the DataSources and actually marshal things
	gadgetCtx.OnPrepare(func() {
		gi, err := gadgetCtx.SerializeGadgetInfo()
		if err != nil {
			logger.Errorf("serializing gadget info: %v", err)
			return
		}

		// datasource mapping; we're sending an array of available DataSources including a
		// DataSourceID; this ID will be used when sending actual data and needs to be remapped
		// to the actual DataSource on the client later on
		dsLookup := make(map[string]uint32)
		for i, ds := range gi.DataSources {
			ds.DataSourceID = uint32(i)
			dsLookup[ds.Name] = ds.DataSourceID
		}

		// todo: skip DataSources we're not interested in

		for _, ds := range gadgetCtx.GetDataSources() {
			dsID := dsLookup[ds.Name()]
			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				d, _ := proto.Marshal(data.Raw())

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
	})

	err = runtime.RunOCIGadget(gadgetCtx)
	if err != nil {
		return err
	}
	return nil
}
