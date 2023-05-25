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

package gadgetservice

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	// TODO: Move!
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/prometheus"
)

type Config struct {
	SocketFile string
}

type Service struct {
	pb.UnimplementedGadgetManagerServer
	config   *Config
	listener net.Listener
	runtime  runtime.Runtime
	logger   logger.Logger
	servers  map[*grpc.Server]struct{}
}

func NewService(defaultLogger logger.Logger) *Service {
	return &Service{
		servers: map[*grpc.Server]struct{}{},
		logger:  defaultLogger,
	}
}

func (s *Service) GetInfo(ctx context.Context, request *pb.InfoRequest) (*pb.InfoResponse, error) {
	catalog, err := s.runtime.GetCatalog()
	if err != nil {
		return nil, fmt.Errorf("get catalog: %w", err)
	}

	catalogJSON, err := json.Marshal(catalog)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}
	return &pb.InfoResponse{
		Version: "1.0", // TODO
		Catalog: catalogJSON,
	}, nil
}

func (s *Service) RunGadget(runGadget pb.GadgetManager_RunGadgetServer) error {
	ctrl, err := runGadget.Recv()
	if err != nil {
		return err
	}

	request := ctrl.GetRunRequest()
	if request == nil {
		return fmt.Errorf("expected first control message to be gadget request")
	}

	// Create a new logger that logs to gRPC and falls back to the standard logger when it failed to send the message
	logger := logger.NewFromGenericLogger(&Logger{
		send:           runGadget.Send,
		level:          logger.Level(request.LogLevel),
		fallbackLogger: s.logger,
	})

	runtime := s.runtime

	gadgetDesc := gadgetregistry.Get(request.GadgetCategory, request.GadgetName)
	if gadgetDesc == nil {
		return fmt.Errorf("gadget not found: %s/%s", request.GadgetCategory, request.GadgetName)
	}

	// Initialize Operators
	err = operators.GetAll().Init(operators.GlobalParamsCollection())
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

	// Create payload buffer
	outputBuffer := make(chan *pb.GadgetEvent, 1024) // TODO: Discuss 1024

	seq := uint32(0)
	var seqLock sync.Mutex

	if parser != nil {
		outputDone := make(chan bool)
		defer func() {
			outputDone <- true
		}()

		parser.SetLogCallback(logger.Logf)
		parser.SetEventCallback(func(ev any) {
			// Marshal messages to JSON
			// Normally, it would be better to have this in the pump below rather than marshaling events that
			// would be dropped anyway. However, we're optimistic that this occurs rarely and instead prevent using
			// ev in another thread.
			data, _ := json.Marshal(ev)
			event := &pb.GadgetEvent{
				Type:    pb.EventTypeGadgetPayload,
				Payload: data,
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
		})

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
	}

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()

	// Send Job ID to client
	err = runGadget.Send(&pb.GadgetEvent{
		Type:    pb.EventTypeGadgetJobID,
		Payload: []byte(runID),
	})
	if err != nil {
		logger.Warnf("sending JobID: %v", err)
		return nil
	}

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		runGadget.Context(),
		runID,
		runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
	)
	defer gadgetCtx.Cancel()

	// Handle commands sent by the client
	go func() {
		defer func() {
			logger.Debugf("runner exited")
		}()
		for {
			msg, err := runGadget.Recv()
			if err != nil {
				gadgetCtx.Cancel()
				return
			}
			switch msg.Event.(type) {
			case *pb.GadgetControlRequest_StopRequest:
				gadgetCtx.Cancel()
				return
			default:
				logger.Warn("unexpected request")
			}
		}
	}()

	// Hand over to runtime
	results, err := runtime.RunGadget(gadgetCtx)
	if err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	// Send result, if any
	for _, result := range results {
		// TODO: when used with fan-out, we need to add the node in here
		event := &pb.GadgetEvent{
			Type:    pb.EventTypeGadgetResult,
			Payload: result.Payload,
		}
		runGadget.Send(event)
	}

	return nil
}

func (s *Service) Run(network, address string, serverOptions ...grpc.ServerOption) error {
	s.runtime = local.New()
	defer s.runtime.Close()

	// Use defaults for now - this will become more important when we fan-out requests also to other
	//  gRPC runtimes
	err := s.runtime.Init(s.runtime.GlobalParamDescs().ToParams())
	if err != nil {
		return fmt.Errorf("initializing runtime: %w", err)
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	s.listener = listener

	server := grpc.NewServer(serverOptions...)
	pb.RegisterGadgetManagerServer(server, s)

	s.servers[server] = struct{}{}

	return server.Serve(s.listener)
}

func (s *Service) Close() {
	for server := range s.servers {
		server.Stop()
		delete(s.servers, server)
	}
}
