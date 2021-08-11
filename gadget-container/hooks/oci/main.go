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
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	"google.golang.org/grpc"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
)

var (
	socketfile string
	hook       string
)

func init() {
	flag.StringVar(&socketfile, "socketfile", "/run/gadgettracermanager.socket", "Socket file")
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
		panic(fmt.Errorf("hook %q not supported\n", hook))
	}

	// Parse state from stdin
	stateBuf, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("cannot read stdin: %v\n", err))
	}

	ociStateID, ociStatePid, err := containerutils.ParseOCIState(stateBuf)
	if err != nil {
		panic(fmt.Errorf("cannot parse stdin: %v\n%s\n", err, string(stateBuf)))
	}

	// Validate state
	if ociStateID == "" || (ociStatePid == 0 && hook == "prestart") {
		panic(fmt.Errorf("invalid OCI state: %v %v", ociStateID, ociStatePid))
	}

	// Connect to the Gadget Tracer Manager
	var client pb.GadgetTracerManagerClient
	var ctx context.Context
	var cancel context.CancelFunc
	conn, err := grpc.Dial("unix://"+socketfile, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	client = pb.NewGadgetTracerManagerClient(conn)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Handle the poststop hook first
	if hook == "poststop" {
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			ContainerId: ociStateID,
		})
		if err != nil {
			panic(err)
		}
		return
	}

	// Get cgroup paths
	cgroupPathV1, cgroupPathV2, err := containerutils.GetCgroupPaths(ociStatePid)
	if err != nil {
		panic(err)
	}
	cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)

	// Get cgroup-v2 id
	cgroupId, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)

	// Get mount namespace ino
	mntns, err := containerutils.GetMntNs(ociStatePid)
	if err != nil {
		panic(err)
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
					panic(fmt.Errorf("cannot parse ppid (%q): %v", ppidStr, err))
				}
				break
			}
		}
	} else {
		panic(fmt.Errorf("cannot parse /proc/PID/status: %v", err))
	}
	cmdline, err := ioutil.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", ppid), "cmdline"))
	if err != nil {
		panic(fmt.Errorf("cannot read /proc/PID/cmdline: %v", err))
	}
	cmdline = bytes.ReplaceAll(cmdline, []byte{0}, []byte("\n"))
	r := regexp.MustCompile("--bundle\n([^\n]*)\n")
	matches := r.FindStringSubmatch(string(cmdline))
	if len(matches) != 2 {
		panic(fmt.Errorf("cannot find bundle in %q: matches=%+v", string(cmdline), matches))
	}
	bundle := matches[1]
	bundleConfig, err := ioutil.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		panic(fmt.Errorf("cannot read config.json from bundle directory %q: %v", bundle, err))
	}

	ociSpec := &ocispec.Spec{}
	err = json.Unmarshal(bundleConfig, ociSpec)
	if err != nil {
		panic(fmt.Errorf("cannot parse config.json: %v\n%s\n", err, string(bundleConfig)))
	}

	mountSources := []string{}
	for _, m := range ociSpec.Mounts {
		mountSources = append(mountSources, m.Source)
	}

	_, err = client.AddContainer(ctx, &pb.ContainerDefinition{
		ContainerId:  ociStateID,
		CgroupPath:   cgroupPathV2WithMountpoint,
		CgroupId:     cgroupId,
		Mntns:        mntns,
		CgroupV1:     cgroupPathV1,
		CgroupV2:     cgroupPathV2,
		MountSources: mountSources,
		Pid:          uint32(ociStatePid),
	})
	if err != nil {
		panic(err)
	}
}
