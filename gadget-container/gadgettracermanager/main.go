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
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

var (
	controller    bool
	serve         bool
	dump          bool
	liveness      bool
	hookMode      string
	socketfile    string
	method        string
	label         string
	tracerid      string
	containerId   string
	cgroupPath    string
	cgroupId      uint64
	namespace     string
	podname       string
	containername string
	containerPid  uint
)

const (
	clientTimeout = 2 * time.Second
)

func init() {
	flag.StringVar(&socketfile, "socketfile", "/run/gadgettracermanager.socket", "Socket file")
	flag.StringVar(&hookMode, "hook-mode", "auto", "how to get containers start/stop notifications (podinformer, fanotify, auto, none)")

	flag.BoolVar(&serve, "serve", false, "Start server")
	flag.BoolVar(&controller, "controller", false, "Enable the controller for custom resources")

	flag.StringVar(&method, "call", "", "Call a method (add-tracer, remove-tracer, receive-stream, add-container, remove-container)")
	flag.StringVar(&label, "label", "", "key=value,key=value labels to use in add-tracer")
	flag.StringVar(&tracerid, "tracerid", "", "tracerid to use in remove-tracer")
	flag.StringVar(&containerId, "containerid", "", "container id to use in add-container or remove-container")
	flag.StringVar(&cgroupPath, "cgrouppath", "", "cgroup path to use in add-container")
	flag.Uint64Var(&cgroupId, "cgroupid", 0, "cgroup id to use in add-container")
	flag.StringVar(&namespace, "namespace", "", "namespace to use in add-container")
	flag.StringVar(&podname, "podname", "", "podname to use in add-container")
	flag.StringVar(&containername, "containername", "", "container name to use in add-container")
	flag.UintVar(&containerPid, "containerpid", 0, "container PID to use in add-container")

	flag.BoolVar(&dump, "dump", false, "Dump state for debugging")
	flag.BoolVar(&liveness, "liveness", false, "Execute as client and perform liveness probe")
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

		ctx, cancel = context.WithTimeout(context.Background(), clientTimeout)
		defer cancel()
	}

	switch method {
	case "":
		// break

	case "add-tracer":
		out, err := client.AddTracer(ctx, &pb.AddTracerRequest{
			Id: tracerid,
			Selector: &pb.ContainerSelector{
				Namespace: namespace,
				Podname:   podname,
				Labels:    labels,
				Name:      containername,
			},
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		fmt.Printf("%+v\n", out.Id)
		os.Exit(0)

	case "remove-tracer":
		_, err := client.RemoveTracer(ctx, &pb.TracerID{
			Id: tracerid,
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		os.Exit(0)

	case "receive-stream":
		stream, err := client.ReceiveStream(context.Background(), &pb.TracerID{
			Id: tracerid,
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		for {
			line, err := stream.Recv()
			if err == io.EOF {
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
			Id:         containerId,
			CgroupPath: cgroupPath,
			CgroupId:   cgroupId,
			Namespace:  namespace,
			Podname:    podname,
			Name:       containername,
			Labels:     labels,
			Pid:        uint32(containerPid),
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		os.Exit(0)

	case "remove-container":
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			Id: containerId,
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

		lis, err := net.Listen("unix", socketfile)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}

		var opts []grpc.ServerOption
		grpcServer := grpc.NewServer(opts...)

		var tracerManager *gadgettracermanager.GadgetTracerManager

		tracerManager, err = gadgettracermanager.NewServer(node, hookMode)

		if err != nil {
			log.Fatalf("failed to create server %v", err)
		}

		pb.RegisterGadgetTracerManagerServer(grpcServer, tracerManager)

		healthserver := health.NewServer()
		healthpb.RegisterHealthServer(grpcServer, healthserver)

		log.Printf("Serving on gRPC socket %s", socketfile)
		go grpcServer.Serve(lis)

		if controller {
			go startController(node, tracerManager)
		}

		exitSignal := make(chan os.Signal)
		signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
		<-exitSignal

		tracerManager.Close()
	}
}
