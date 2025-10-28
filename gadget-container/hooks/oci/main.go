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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service/api"
	kubemanagertypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/types"
)

var (
	socketfile string
	hook       string
)

func init() {
	flag.StringVar(&socketfile, "socketfile", kubemanagertypes.DefaultHookAndLivenessSocketFile, "Socket file")
	flag.StringVar(&hook, "hook", "", "OCI hook: prestart or poststop")
}

func main() {
	// Parse arguments
	flag.Parse()
	if flag.NArg() > 0 {
		flag.PrintDefaults()
		panic(fmt.Errorf("invalid command"))
	}

	if hook != "prestart" && hook != "poststop" {
		panic(fmt.Errorf("hook %q not supported", hook))
	}

	// Parse state from stdin
	stateBuf, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("reading stdin: %w", err))
	}

	ociStateID, ociStatePid, err := containerutils.ParseOCIState(stateBuf)
	if err != nil {
		panic(fmt.Errorf("parsing stdin: %w\n%s", err, string(stateBuf)))
	}

	// Validate state
	if ociStateID == "" || (ociStatePid == 0 && hook == "prestart") {
		panic(fmt.Errorf("invalid OCI state: %v %v", ociStateID, ociStatePid))
	}

	// Connect to the Hook Service
	var client pb.HookServiceClient
	var ctx context.Context
	var cancel context.CancelFunc

	conn, err := grpc.NewClient("unix://"+socketfile, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client = pb.NewHookServiceClient(conn)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Handle the poststop hook first
	if hook == "poststop" {
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			Id: ociStateID,
		})
		if err != nil {
			panic(err)
		}
		return
	}

	// Get bundle directory and OCI spec (config.json)
	ppid := 0
	if statusFile, err := os.Open(filepath.Join("/proc", fmt.Sprintf("%d", ociStatePid), "status")); err == nil {
		defer statusFile.Close()
		reader := bufio.NewReader(statusFile)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.HasPrefix(line, "PPid:\t") {
				ppidStr := strings.TrimPrefix(line, "PPid:\t")
				ppidStr = strings.TrimSuffix(ppidStr, "\n")
				ppid, err = strconv.Atoi(ppidStr)
				if err != nil {
					panic(fmt.Errorf("parsing ppid (%q): %w", ppidStr, err))
				}
				break
			}
		}
	} else {
		panic(fmt.Errorf("parsing /proc/PID/status: %w", err))
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", ppid), "cmdline"))
	if err != nil {
		panic(fmt.Errorf("reading /proc/PID/cmdline: %w", err))
	}
	cmdline = bytes.ReplaceAll(cmdline, []byte{0}, []byte("\n"))
	r := regexp.MustCompile("--bundle\n([^\n]*)\n")
	matches := r.FindStringSubmatch(string(cmdline))
	if len(matches) != 2 {
		panic(fmt.Errorf("finding bundle in %q: matches=%+v", string(cmdline), matches))
	}
	bundle := matches[1]
	bundleConfig, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		panic(fmt.Errorf("reading config.json from bundle directory %q: %w", bundle, err))
	}

	ociSpec := &ocispec.Spec{}
	err = json.Unmarshal(bundleConfig, ociSpec)
	if err != nil {
		panic(fmt.Errorf("parsing config.json: %w\n%s", err, string(bundleConfig)))
	}

	_, err = client.AddContainer(ctx, &pb.ContainerDefinition{
		Id:        ociStateID,
		Pid:       uint32(ociStatePid),
		OciConfig: string(bundleConfig),
	})
	if err != nil {
		panic(err)
	}
}
