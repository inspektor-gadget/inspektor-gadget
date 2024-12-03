// Copyright 2019-2024 The Inspektor Gadget authors
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
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	// Import this early to set the environment variable before any other package is imported
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/environment/k8s"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	k8sconfigmapstore "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/store/k8s-configmap-store"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	// This is a blank include that actually imports all gadgets
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/all-gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"

	// Blank import for some operators
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/btfgen"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/eventgen"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/filter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/limiter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/otel-metrics"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/sort"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/uidgidresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"

	gadgetservice "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/gadgettracermanagerloglevel"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

var (
	controller          bool
	serve               bool
	liveness            bool
	fallbackPodInformer bool
	dump                string
	hookMode            string
	socketfile          string
	gadgetServiceHost   string
	method              string
	label               string
	tracerid            string
	containerID         string
	namespace           string
	podname             string
	containername       string
	containerPid        uint
)

var clientTimeout = 2 * time.Second

func init() {
	flag.StringVar(&socketfile, "socketfile", "/run/gadgettracermanager.socket", "Socket file")
	flag.StringVar(&gadgetServiceHost, "service-host", fmt.Sprintf("tcp://127.0.0.1:%d", api.GadgetServicePort), "Socket address for gadget service")
	flag.StringVar(&hookMode, "hook-mode", "auto", "how to get containers start/stop notifications (podinformer, fanotify, auto, none)")

	flag.BoolVar(&serve, "serve", false, "Start server")
	flag.BoolVar(&controller, "controller", false, "Enable the controller for custom resources")

	flag.StringVar(&method, "call", "", "Call a method (add-tracer, remove-tracer, receive-stream, add-container, remove-container)")
	flag.StringVar(&label, "label", "", "key=value,key=value labels to use in add-tracer")
	flag.StringVar(&tracerid, "tracerid", "", "tracerid to use in receive-stream")
	flag.StringVar(&containerID, "containerid", "", "container id to use in add-container or remove-container")
	flag.StringVar(&namespace, "namespace", "", "namespace to use in add-container")
	flag.StringVar(&podname, "podname", "", "podname to use in add-container")
	flag.StringVar(&containername, "containername", "", "container name to use in add-container")
	flag.UintVar(&containerPid, "containerpid", 0, "container PID to use in add-container")

	flag.StringVar(&dump, "dump", "", "Dump state for debugging specifying the items to print: containers, traces, stacks, all")

	flag.BoolVar(&liveness, "liveness", false, "Execute as client and perform liveness probe")
	flag.BoolVar(&fallbackPodInformer, "fallback-podinformer", true, "Use pod informer as a fallback for main hook")
}

func main() {
	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Println("invalid command")
		flag.PrintDefaults()
		os.Exit(1)
	}
	tracerManLogLvl := gadgettracermanagerloglevel.LogLevel()
	log.SetLevel(tracerManLogLvl)
	labels := []*pb.Label{}
	if label != "" {
		pairs := strings.Split(label, ",")
		for _, pair := range pairs {
			kv := strings.Split(pair, "=")
			if len(kv) != 2 {
				fmt.Printf("invalid key=value[,key=value,...] %q\n", label)
				flag.PrintDefaults()
				os.Exit(1)
			}
			labels = append(labels, &pb.Label{Key: kv[0], Value: kv[1]})
		}
	}

	var client pb.GadgetTracerManagerClient
	var ctx context.Context
	var cancel context.CancelFunc
	var conn *grpc.ClientConn
	if liveness || dump != "" || method != "" {
		var err error
		//nolint:staticcheck
		conn, err = grpc.Dial("unix://"+socketfile, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("fail to dial: %v", err)
		}
		defer conn.Close()
		client = pb.NewGadgetTracerManagerClient(conn)

		if liveness {
			// Let's cover the cases where timeoutSeconds is not respected. See
			// https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#configure-probes.
			// IMPORTANT: Consider that setting timeoutSeconds to a value larger
			// than clientTimeout will have no effect. Check further details in
			// https://github.com/inspektor-gadget/inspektor-gadget/issues/940.
			clientTimeout = time.Minute
		}

		ctx, cancel = context.WithTimeout(context.Background(), clientTimeout)
		defer cancel()
	}

	switch method {
	case "":
		// break

	case "receive-stream":
		stream, err := client.ReceiveStream(context.Background(), &pb.TracerID{
			Id: tracerid,
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		for {
			line, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				log.Fatalf("%v.ReceiveStream(_) = _, %v", client, err)
			}
			fmt.Println(line.Line)
		}

		os.Exit(0)

	case "add-container":
		_, err := client.AddContainer(ctx, &pb.ContainerDefinition{
			Id:        containerID,
			Pid:       uint32(containerPid),
			OciConfig: "",
			Namespace: namespace,
			Podname:   podname,
			Name:      containername,
			Labels:    labels,
			LabelsSet: label != "",
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		os.Exit(0)

	case "remove-container":
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			Id: containerID,
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		os.Exit(0)

	default:
		fmt.Printf("invalid method %q\n", method)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if dump != "" {
		out, err := client.DumpState(ctx, &pb.DumpStateRequest{})
		if err != nil {
			log.Fatalf("%v", err)
		}
		switch dump {
		case "":
			// break

		case "containers":
			fmt.Println(out.Containers)
			os.Exit(0)

		case "traces":
			fmt.Println(out.Traces)
			os.Exit(0)

		case "stacks":
			fmt.Println(out.Stacks)
			os.Exit(0)

		case "all":
			fmt.Println(out.Containers, out.Traces, out.Stacks)
			os.Exit(0)

		default:
			fmt.Printf("invalid method %q\n", method)
			flag.PrintDefaults()
			os.Exit(1)
		}

	}

	if liveness {
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
		if experimental.Enabled() {
			log.Info("Experimental features enabled")
		}

		config.Config = config.NewWithPath(gadgettracermanagerconfig.ConfigPath)
		if err := config.Config.ReadInConfig(); err != nil {
			log.Warnf("reading config: %v", err)
		}

		operators.RegisterDataOperator(ocihandler.OciHandler)

		hostConfig := host.Config{
			AutoMountFilesystems: true,
		}
		err := host.Init(hostConfig)
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

		node := os.Getenv("NODE_NAME")
		if node == "" {
			log.Fatalf("Environment variable NODE_NAME not set")
		}

		lis, err := net.Listen("unix", socketfile)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}

		var opts []grpc.ServerOption
		grpcServer := grpc.NewServer(opts...)

		var tracerManager *gadgettracermanager.GadgetTracerManager

		tracerManager, err = gadgettracermanager.NewServer(&gadgettracermanager.Conf{
			NodeName:            node,
			HookMode:            hookMode,
			FallbackPodInformer: fallbackPodInformer,
		})
		if err != nil {
			log.Fatalf("failed to create Gadget Tracer Manager server: %v", err)
		}

		pb.RegisterGadgetTracerManagerServer(grpcServer, tracerManager)

		healthserver := health.NewServer()
		healthpb.RegisterHealthServer(grpcServer, healthserver)

		log.Printf("Serving on gRPC socket %s", socketfile)
		go grpcServer.Serve(lis)

		if controller {
			go startController(node, tracerManager)
		}

		stringBufferLength := config.Config.GetString(gadgettracermanagerconfig.EventsBufferLengthKey)
		if stringBufferLength == "" {
			log.Warnf("EVENTS_BUFFER_LENGTH is deprecated. Use %q instead in configmap", gadgettracermanagerconfig.EventsBufferLengthKey)
			stringBufferLength = os.Getenv("EVENTS_BUFFER_LENGTH")
		}
		if stringBufferLength == "" {
			log.Fatalf("Environment variable EVENTS_BUFFER_LENGTH or config not set")
		}

		bufferLength, err := strconv.ParseUint(stringBufferLength, 10, 64)
		if err != nil {
			log.Fatalf("Parsing EVENTS_BUFFER_LENGTH %q: %v", stringBufferLength, err)
		}
		service := gadgetservice.NewService(log.StandardLogger())
		service.SetEventBufferLength(bufferLength)

		mgr, err := instancemanager.New(local.New())
		if err != nil {
			log.Fatalf("initializing manager: %v", err)
		}

		store, err := k8sconfigmapstore.New(mgr)
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
		tracerManager.Close()
	}
}
