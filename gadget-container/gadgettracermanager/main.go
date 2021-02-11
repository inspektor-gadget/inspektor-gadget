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
	"log"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

var (
	serve         bool
	dump          bool
	podInformer   bool
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
)

func init() {
	flag.StringVar(&socketfile, "socketfile", "/run/gadgettracermanager.socket", "Socket file")

	flag.BoolVar(&serve, "serve", false, "Start server")
	flag.BoolVar(&podInformer, "podinformer", false, "Enable a Pod Informer to get Pod events from k8s API server")

	flag.StringVar(&method, "call", "", "Call a method (add-tracer, remove-tracer, add-container, remove-container)")
	flag.StringVar(&label, "label", "", "key=value,key=value labels to use in add-tracer")
	flag.StringVar(&tracerid, "tracerid", "", "tracerid to use in remove-tracer")
	flag.StringVar(&containerId, "containerid", "", "container id to use in add-container or remove-container")
	flag.StringVar(&cgroupPath, "cgrouppath", "", "cgroup path to use in add-container")
	flag.Uint64Var(&cgroupId, "cgroupid", 0, "cgroup id to use in add-container")
	flag.StringVar(&namespace, "namespace", "", "namespace to use in add-container")
	flag.StringVar(&podname, "podname", "", "podname to use in add-container")
	flag.StringVar(&containername, "containername", "", "container name to use in add-container")

	flag.BoolVar(&dump, "dump", false, "Dump state for debugging")
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
	if dump || method != "" {
		conn, err := grpc.Dial("unix://"+socketfile, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("fail to dial: %v", err)
		}
		defer conn.Close()
		client = pb.NewGadgetTracerManagerClient(conn)

		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}

	switch method {
	case "":
		// break

	case "add-tracer":
		out, err := client.AddTracer(ctx, &pb.AddTracerRequest{
			Id: tracerid,
			Selector: &pb.ContainerSelector{
				Namespace:     namespace,
				Podname:       podname,
				Labels:        labels,
				ContainerName: containername,
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

	case "add-container":
		_, err := client.AddContainer(ctx, &pb.ContainerDefinition{
			ContainerId:   containerId,
			CgroupPath:    cgroupPath,
			CgroupId:      cgroupId,
			Namespace:     namespace,
			Podname:       podname,
			ContainerName: containername,
			Labels:        labels,
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
		os.Exit(0)

	case "remove-container":
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			ContainerId: containerId,
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

	if serve {
		lis, err := net.Listen("unix", socketfile)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}

		node := os.Getenv("NODE_NAME")
		if node == "" {
			log.Fatalf("Environment variable NODE_NAME not set")
		}

		var opts []grpc.ServerOption
		grpcServer := grpc.NewServer(opts...)

		var tracerManager *gadgettracermanager.GadgetTracerManager

		if podInformer {
			tracerManager, err = gadgettracermanager.NewServerWithPodInformer(node)
		} else {
			tracerManager, err = gadgettracermanager.NewServer(node)
		}

		if err != nil {
			log.Fatalf("failed to create server %v", err)
		}

		pb.RegisterGadgetTracerManagerServer(grpcServer, tracerManager)
		grpcServer.Serve(lis)
	}
}
