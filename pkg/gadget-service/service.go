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

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
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
	api.UnimplementedBuiltInGadgetManagerServer
	api.UnimplementedGadgetManagerServer
	instanceMgr       *instancemanager.Manager
	listener          net.Listener
	runtime           runtime.Runtime
	logger            logger.Logger
	servers           map[*grpc.Server]struct{}
	eventBufferLength uint64

	// operators stores all global parameters for DataOperators (non-legacy)
	operators map[operators.DataOperator]*params.Params
}

func NewService(defaultLogger logger.Logger) *Service {
	ops := make(map[operators.DataOperator]*params.Params)
	for _, op := range operators.GetDataOperators() {
		ops[op] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}
	return &Service{
		servers:   map[*grpc.Server]struct{}{},
		logger:    defaultLogger,
		operators: ops,
	}
}

func (s *Service) SetEventBufferLength(val uint64) {
	s.eventBufferLength = val
}

func (s *Service) SetInstanceManager(mgr *instancemanager.Manager) {
	s.instanceMgr = mgr
	mgr.Service = s
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
		Version:       "1.0", // TODO
		Catalog:       catalogJSON,
		Experimental:  experimental.Enabled(),
		ServerVersion: version.Version().String(),
	}, nil
}

func (s *Service) RunBuiltInGadget(runGadget api.BuiltInGadgetManager_RunBuiltInGadgetServer) error {
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
	gadgetCtx := gadgetcontext.NewBuiltIn(
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
			case *api.BuiltInGadgetControlRequest_StopRequest:
				gadgetCtx.Cancel()
				return
			default:
				logger.Warn("unexpected request")
			}
		}
	}()

	// Hand over to runtime
	results, err := runtime.RunBuiltInGadget(gadgetCtx)
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
	api.RegisterBuiltInGadgetManagerServer(server, s)
	api.RegisterGadgetManagerServer(server, s)
	api.RegisterGadgetInstanceManagerServer(server, s.instanceMgr)

	s.servers[server] = struct{}{}

	err = s.initOperators()
	if err != nil {
		return fmt.Errorf("initializing operators: %w", err)
	}

	err = s.instanceMgr.Store.LoadStoredGadgets()
	if err != nil {
		return fmt.Errorf("loading stored gadgets: %w", err)
	}

	return server.Serve(s.listener)
}

func (s *Service) Close() {
	for server := range s.servers {
		server.Stop()
		delete(s.servers, server)
	}
}
