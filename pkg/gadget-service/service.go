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

package gadgetservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

type RunConfig struct {
	// SocketType can be either unix or tcp
	SocketType string

	// SocketPath must be the path to a unix socket or ip:port, depending on
	// SocketType
	SocketPath string

	// If SocketGID != 0 and a unix socket is used, the ownership of that socket
	// will be changed to the given SocketGID
	SocketGID int
}

type Service struct {
	api.UnimplementedGadgetManagerServer
	api.UnimplementedOCIGadgetManagerServer
	listener          net.Listener
	runtime           runtime.Runtime
	logger            logger.Logger
	servers           map[*grpc.Server]struct{}
	eventBufferLength uint64
}

func NewService(defaultLogger logger.Logger, length uint64) *Service {
	return &Service{
		servers:           map[*grpc.Server]struct{}{},
		logger:            defaultLogger,
		eventBufferLength: length,
	}
}

func (s *Service) GetInfo(ctx context.Context, request *api.InfoRequest) (*api.InfoResponse, error) {
	catalog, err := s.runtime.GetCatalog()
	if err != nil {
		return nil, fmt.Errorf("get catalog: %w", err)
	}

	catalogJSON, err := json.Marshal(catalog)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}
	return &api.InfoResponse{
		Version:      "1.0", // TODO
		Catalog:      catalogJSON,
		Experimental: experimental.Enabled(),
	}, nil
}

func (s *Service) GetGadgetInfo(ctx context.Context, req *api.GetGadgetInfoRequest) (*api.GetGadgetInfoResponse, error) {
	gadgetDesc := gadgetregistry.Get(gadgets.CategoryNone, "run")
	if gadgetDesc == nil {
		return nil, errors.New("run gadget not found")
	}

	params := gadgetDesc.ParamDescs().ToParams()
	params.CopyFromMap(req.Params, "")

	ret, err := s.runtime.GetGadgetInfo(ctx, gadgetDesc, params, req.Args)
	if err != nil {
		return nil, fmt.Errorf("getting gadget info: %w", err)
	}

	retJSON, err := json.Marshal(ret)
	if err != nil {
		return nil, fmt.Errorf("marshal gadget info response: %w", err)
	}

	return &api.GetGadgetInfoResponse{
		Info: retJSON,
	}, nil
}

func (s *Service) GetOCIGadgetInfo(ctx context.Context, req *api.GetOCIGadgetInfoRequest) (*api.GetOCIGadgetInfoResponse, error) {
	if req.Version != api.VersionGadgetInfo {
		return nil, fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetInfo, req.Version)
	}

	if len(req.Args) < 1 {
		return nil, fmt.Errorf("invalid arguments")
	}

	gadgetCtx := gadgetcontext.NewSimple(ctx, req.Args[0], s.logger)
	gi, err := s.runtime.GetOCIGadgetInfo(gadgetCtx, nil, req.Args)
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

	gadgetCtx := gadgetcontext.NewSimple(runGadget.Context(), ociRequest.Url, logger)

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
			logger.Errorf("could not serialize gadget info: %v", err)
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
		runGadget.Send(&api.GadgetEvent{
			Type:    api.EventTypeGadgetInfo,
			Payload: d,
		})
	})

	err = runtime.RunOCIGadget(gadgetCtx)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RunGadget(runGadget api.GadgetManager_RunGadgetServer) error {
	ctrl, err := runGadget.Recv()
	if err != nil {
		return err
	}

	request := ctrl.GetRunRequest()
	if request == nil {
		return fmt.Errorf("expected first control message to be gadget run request")
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

	parser := gadgetDesc.Parser()

	runtimeParams := runtime.ParamDescs().ToParams()
	gType := gadgetDesc.Type()

	gadgetParamDescs := gadgetDesc.ParamDescs()
	// TODO: do we need to update gType before calling this?
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, gType, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()
	err = gadgets.ParamsFromMap(request.Params, gadgetParams, runtimeParams, operatorParams)
	if err != nil {
		return fmt.Errorf("setting parameters: %w", err)
	}

	var gadgetInfo *runTypes.GadgetInfo

	if c, ok := gadgetDesc.(runTypes.RunGadgetDesc); ok {
		gadgetInfo, err = s.runtime.GetGadgetInfo(runGadget.Context(), gadgetDesc, gadgetParams, request.Args)
		if err != nil {
			return fmt.Errorf("getting gadget info: %w", err)
		}
		parser, err = c.CustomParser(gadgetInfo)
		if err != nil {
			return fmt.Errorf("calling custom parser: %w", err)
		}

		// Update gadget parameters to take ebpf params into consideration
		for _, p := range gadgetInfo.GadgetMetadata.EBPFParams {
			p := p
			gadgetParamDescs.Add(&p.ParamDesc)
		}
		gadgetParams = gadgetParamDescs.ToParams()
		err = gadgetParams.CopyFromMap(request.Params, "")
		if err != nil {
			return fmt.Errorf("setting parameters: %w", err)
		}

	}

	// Create payload buffer
	outputBuffer := make(chan *api.GadgetEvent, s.eventBufferLength)

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
			event := &api.GadgetEvent{
				Type:    api.EventTypeGadgetPayload,
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
	err = runGadget.Send(&api.GadgetEvent{
		Type:    api.EventTypeGadgetJobID,
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
		request.Args,
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
		gadgetInfo,
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
			case *api.GadgetControlRequest_StopRequest:
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
		event := &api.GadgetEvent{
			Type:    api.EventTypeGadgetResult,
			Payload: result.Payload,
		}
		runGadget.Send(event)
	}

	return nil
}

func newUnixListener(address string, gid int) (net.Listener, error) {
	if err := os.Remove(address); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing existing unix socket at %q: %w", address, err)
	}

	// If the given path is the default, try to create it and change its permissions; if it's not the default, it is
	// up to the user to manage it
	if "unix://"+address == api.DefaultDaemonPath {
		dir := filepath.Dir(address)
		if err := os.MkdirAll(dir, 0o710); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("creating directory %q: %w", dir, err)
		}
		if err := os.Chown(dir, 0, gid); err != nil {
			return nil, fmt.Errorf("chown directory %q: %w", dir, err)
		}
	}

	// Set umask to 0o777 to avoid a race condition between creating the listener and applying its permissionss
	oldMask := syscall.Umask(0o777)
	defer syscall.Umask(oldMask)

	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, fmt.Errorf("creating unix listener at %q: %w", address, err)
	}
	if err := os.Chown(address, 0, gid); err != nil {
		listener.Close()
		return nil, fmt.Errorf("chown unix socket %q: %w", address, err)
	}
	if err := os.Chmod(address, 0o660); err != nil {
		listener.Close()
		return nil, fmt.Errorf("chmod unix socket %q: %w", address, err)
	}
	return listener, nil
}

func (s *Service) Run(runConfig RunConfig, serverOptions ...grpc.ServerOption) error {
	s.runtime = local.New()
	defer s.runtime.Close()

	// Use defaults for now - this will become more important when we fan-out requests also to other
	//  gRPC runtimes
	err := s.runtime.Init(s.runtime.GlobalParamDescs().ToParams())
	if err != nil {
		return fmt.Errorf("initializing runtime: %w", err)
	}

	switch runConfig.SocketType {
	case "unix":
		listener, err := newUnixListener(runConfig.SocketPath, runConfig.SocketGID)
		if err != nil {
			return fmt.Errorf("creating unix listener: %w", err)
		}
		s.listener = listener
	case "tcp":
		listener, err := net.Listen(runConfig.SocketType, runConfig.SocketPath)
		if err != nil {
			return fmt.Errorf("creating listener: %w", err)
		}
		s.listener = listener
	default:
		return fmt.Errorf("invalid socket type: %s", runConfig.SocketType)
	}

	server := grpc.NewServer(serverOptions...)
	api.RegisterGadgetManagerServer(server, s)
	api.RegisterOCIGadgetManagerServer(server, s)

	s.servers[server] = struct{}{}

	return server.Serve(s.listener)
}

func (s *Service) Close() {
	for server := range s.servers {
		server.Stop()
		delete(s.servers, server)
	}
}
