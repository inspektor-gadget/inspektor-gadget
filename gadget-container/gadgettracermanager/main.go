// Copyright 2019-2025 The Inspektor Gadget authors
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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	// Import this early to set the environment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/k8s"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	k8sconfigmapstore "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/store/k8s-configmap-store"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"

	// import for gadgettracermanager entrypoint"
	"github.com/inspektor-gadget/inspektor-gadget/gadget-container/entrypoint"
	// Blank import for some operators
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/btfgen"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/env"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/filter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/limiter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-logs"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-metrics"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/process"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/sort"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/uidgidresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ustack"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"

	// Symbolizers (all)
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer/debuginfod"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer/symtab"

	gadgetservice "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	kubemanagertypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

var (
	serve             bool
	liveness          bool
	socketfile        string
	gadgetServiceHost string
)

var clientTimeout = 2 * time.Second

func init() {
	flag.StringVar(&socketfile, "liveness-socketfile", kubemanagertypes.DefaultHookAndLivenessSocketFile, "Path to socket file for liveness checks")
	flag.StringVar(&gadgetServiceHost, "service-host", fmt.Sprintf("tcp://127.0.0.1:%d", api.GadgetServicePort), "Socket address for gadget service")

	flag.BoolVar(&serve, "serve", false, "Start server")
	flag.BoolVar(&liveness, "liveness", false, "Execute as client and perform liveness probe")
}

func main() {
	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Println("invalid command")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if liveness {
		var ctx context.Context
		var cancel context.CancelFunc
		var conn *grpc.ClientConn

		var err error

		conn, err = grpc.NewClient("unix://"+socketfile, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Printf("Gadget Tracer Manager health check failed to dial: %v", err)
			os.Exit(1)
		}
		defer conn.Close()

		// Let's cover the cases where timeoutSeconds is not respected. See
		// https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#configure-probes.
		// IMPORTANT: Consider that setting timeoutSeconds to a value larger
		// than clientTimeout will have no effect. Check further details in
		// https://github.com/inspektor-gadget/inspektor-gadget/issues/940.
		clientTimeout = time.Minute
		ctx, cancel = context.WithTimeout(context.Background(), clientTimeout)
		defer cancel()

		resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		if err != nil {
			stat := status.Convert(err)

			if stat.Code() == codes.DeadlineExceeded {
				fmt.Printf("Gadget Tracer Manager health RPC reached the timeout: %v", clientTimeout)
			} else {
				fmt.Printf("Gadget Tracer Manager health RPC failed: '%s'", stat.Message())
			}

			os.Exit(1)
		}

		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			fmt.Printf("Gadget Tracer Manager unhealthy: %s", resp.GetStatus().String())
			os.Exit(1)
		}

		fmt.Printf("Gadget Tracer Manager healthy: %s", resp.GetStatus().String())
		os.Exit(0)
	}

	if serve {
		if err := gadgettracermanagerconfig.Init(); err != nil {
			log.Fatalf("Initializing config: %v", err)
		}

		log.Infof("Inspektor Gadget version: %s", version.Version().String())
		log.Infof("Inspektor Gadget User Agent: %s", version.UserAgent())

		logLevel, err := log.ParseLevel(config.Config.GetString(gadgettracermanagerconfig.DaemonLogLevel))
		if err != nil {
			log.Fatalf("Parsing log level %q: %v", logLevel, err)
		}
		log.SetLevel(logLevel)
		log.Infof("Config: %s=%s", gadgettracermanagerconfig.DaemonLogLevel, logLevel)

		if experimental.Enabled() {
			log.Info("Experimental features enabled")
		}

		operators.RegisterDataOperator(ocihandler.OciHandler)

		hostConfig := host.Config{
			AutoMountFilesystems: true,
		}
		err = host.Init(hostConfig)
		if err != nil {
			log.Fatalf("host.Init() failed: %v", err)
		}

		hostPidNs, err := host.IsHostPidNs()
		if err != nil {
			log.Fatalf("Detecting pid namespace: %v", err)
		}
		log.Infof("HostPID=%t", hostPidNs)
		hostNetNs, err := host.IsHostNetNs()
		if err != nil {
			log.Fatalf("Detecting net namespace: %v", err)
		}
		log.Infof("HostNetwork=%t", hostNetNs)
		hostCgroupNs, err := host.IsHostCgroupNs()
		if err != nil {
			log.Fatalf("Detecting cgroup namespace: %v", err)
		}
		log.Infof("HostCgroup=%t", hostCgroupNs)

		if err = entrypoint.Init(); err != nil {
			log.Fatalf("entrypoint.Init() failed: %v", err)
		}

		stringBufferLength := config.Config.GetString(gadgettracermanagerconfig.EventsBufferLengthKey)
		log.Infof("Config: %s=%s", gadgettracermanagerconfig.EventsBufferLengthKey, stringBufferLength)
		bufferLength, err := strconv.ParseUint(stringBufferLength, 10, 64)
		if err != nil {
			log.Fatalf("Parsing events-buffer-length %q: %v", stringBufferLength, err)
		}
		service := gadgetservice.NewService(log.StandardLogger())
		service.SetEventBufferLength(bufferLength)

		mgr, err := instancemanager.New(local.New())
		if err != nil {
			log.Fatalf("initializing manager: %v", err)
		}

		gadgetNs := config.Config.GetString(gadgettracermanagerconfig.GadgetNamespace)
		log.Infof("Config: %s=%s", gadgettracermanagerconfig.GadgetNamespace, gadgetNs)
		if gadgetNs == "" {
			log.Fatalf("gadget namespace must not be empty")
		}

		store, err := k8sconfigmapstore.New(mgr, gadgetNs)
		if err != nil {
			log.Fatalf("initializing store: %v", err)
		}

		service.SetStore(store)
		service.SetInstanceManager(mgr)

		socketType, socketPath, err := api.ParseSocketAddress(gadgetServiceHost)
		if err != nil {
			log.Fatalf("invalid service host: %v", err)
		}
		go func() {
			err := service.Run(gadgetservice.RunConfig{
				SocketType: socketType,
				SocketPath: socketPath,
			})
			if err != nil {
				log.Fatalf("starting gadget service: %v", err)
			}
		}()

		exitSignal := make(chan os.Signal, 1)
		signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
		<-exitSignal

		service.Close()
	}
}
