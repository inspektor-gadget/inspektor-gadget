// Copyright 2023-2025 The Inspektor Gadget authors
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
	"strings"
	"syscall"

	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/store"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
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
	api.UnimplementedGadgetInstanceManagerServer
	instanceMgr       *instancemanager.Manager
	store             store.Store
	listener          net.Listener
	runtime           runtime.Runtime
	logger            logger.Logger
	servers           map[*grpc.Server]struct{}
	eventBufferLength uint64

	// operators stores all global parameters for DataOperators (non-legacy)
	operators map[operators.DataOperator]*params.Params

	// metrics (only covering image-based gadgets)
	ctrGetGadgetInfo metric.Int64Counter
	ctrRunGadget     metric.Int64Counter
	ctrAttachGadget  metric.Int64Counter
}

func NewService(defaultLogger logger.Logger) *Service {
	ops := make(map[operators.DataOperator]*params.Params)
	for _, op := range operators.GetDataOperators() {
		ops[op] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}

	svc := &Service{
		servers:   map[*grpc.Server]struct{}{},
		logger:    defaultLogger,
		operators: ops,
	}

	svc.ctrGetGadgetInfo, _ = metrics.Int64Counter("ig_grpc_get_gadget_info",
		metric.WithUnit("{instance}"),
		metric.WithDescription("Number of GetGadgetInfo() gRPC requests"),
	)
	svc.ctrRunGadget, _ = metrics.Int64Counter("ig_grpc_run_gadget",
		metric.WithUnit("{request}"),
		metric.WithDescription("Number of RunGadget()/Run gRPC requests"),
	)
	svc.ctrAttachGadget, _ = metrics.Int64Counter("ig_grpc_attach_gadget",
		metric.WithUnit("{request}"),
		metric.WithDescription("Number of RunGadget()/Attach gRPC requests"),
	)

	return svc
}

func (s *Service) SetEventBufferLength(val uint64) {
	s.eventBufferLength = val
}

func (s *Service) SetInstanceManager(mgr *instancemanager.Manager) {
	s.instanceMgr = mgr
	mgr.Service = s
}

func (s *Service) SetStore(store store.Store) {
	s.store = store
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

	// Set the global parameters for all operators using config file
	for op, p := range s.operators {
		for pk := range p.ParamMap() {
			ck := config.OperatorKey + "." + op.Name() + "." + pk
			if config.Config.IsSet(ck) {
				var value string

				v := config.Config.Get(ck)
				switch v.(type) {
				default:
					value = config.Config.GetString(ck)
				case []interface{}:
					slice := config.Config.GetStringSlice(ck)
					value = strings.Join(slice, ",")
				}

				err := p.Set(pk, value)
				if err != nil {
					return fmt.Errorf("setting operator parameter %s: %w", ck, err)
				}
			}
		}
	}

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

	if s.store != nil {
		api.RegisterGadgetInstanceManagerServer(server, s)
	}

	s.servers[server] = struct{}{}

	err = s.initOperators()
	if err != nil {
		return fmt.Errorf("initializing operators: %w", err)
	}

	if s.store != nil {
		err = s.store.ResumeStoredGadgets()
		if err != nil {
			return fmt.Errorf("loading stored gadgets: %w", err)
		}
	}

	return server.Serve(s.listener)
}

func (s *Service) Close() {
	for server := range s.servers {
		server.Stop()
		delete(s.servers, server)
	}
}
