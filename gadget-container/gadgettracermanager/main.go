// Copyright 2019-2021 The Inspektor Gadget authors
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
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
)

var (
	controller          bool
	serve               bool
	dump                bool
	liveness            bool
	fallbackPodInformer bool
	hookMode            string
	socketfile          string
	listenaddr          string
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
	flag.StringVar(&listenaddr, "listenaddr", "127.0.0.1:7080", "GRPC listen address")
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

	flag.BoolVar(&dump, "dump", false, "Dump state for debugging")
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
	if liveness || dump || method != "" {
		var err error
		conn, err = grpc.Dial("unix://"+socketfile, grpc.WithInsecure())
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

	if dump {
		out, err := client.DumpState(ctx, &pb.DumpStateRequest{})
		if err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Println(out.State)
		os.Exit(0)
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
		node := os.Getenv("NODE_NAME")
		if node == "" {
			log.Fatalf("Environment variable NODE_NAME not set")
		}

		unixListener, err := net.Listen("unix", socketfile)
		if err != nil {
			log.Fatalf("failed to listen (unix socket): %v", err)
		}

		tcpListener, err := net.Listen("tcp", listenaddr)
		if err != nil {
			log.Fatalf("failed to listen (tcp): %v", err)
		}

		var tracerManager *gadgettracermanager.GadgetTracerManager

		tracerManager, err = gadgettracermanager.NewServer(&gadgettracermanager.Conf{
			NodeName:            node,
			HookMode:            hookMode,
			FallbackPodInformer: fallbackPodInformer,
		})
		if err != nil {
			log.Fatalf("failed to create Gadget Tracer Manager server: %v", err)
		}

		// Get TLS configuration (including a new certificate) for our gRPC endpoint
		tlsConfig, err := getTLSConfig(node)
		if err != nil {
			log.Fatalf("failed to get TLS config for gRPC: %v", err)
		}

		// Local (unix socket, legacy) gRPC service
		grpcServerUnix := grpc.NewServer()

		// TCP bases gRPC service
		var opts []grpc.ServerOption
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		opts = append(opts, grpc.UnaryInterceptor(unaryInterceptor()))
		opts = append(opts, grpc.StreamInterceptor(streamInterceptor()))
		grpcServerTCP := grpc.NewServer(opts...)

		// Register GadgetTracerManagerServer with both gRPC endpoints
		pb.RegisterGadgetTracerManagerServer(grpcServerUnix, tracerManager)
		pb.RegisterGadgetTracerManagerServer(grpcServerTCP, tracerManager)

		healthserver := health.NewServer()
		healthpb.RegisterHealthServer(grpcServerUnix, healthserver)

		log.Printf("Serving gRPC: unix://%s", socketfile)
		log.Printf("Serving gRPC: %s", listenaddr)
		go grpcServerUnix.Serve(unixListener)
		go grpcServerTCP.Serve(tcpListener)

		if controller {
			go startController(node, tracerManager)
		}

		exitSignal := make(chan os.Signal, 1)
		signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
		<-exitSignal

		tracerManager.Close()
	}
}
