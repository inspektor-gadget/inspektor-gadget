// Copyright 2019-2022 The Inspektor Gadget authors
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

package containerutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/crio"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/docker"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/podman"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

var AvailableRuntimes = []string{
	runtimeclient.DockerName,
	runtimeclient.ContainerdName,
	runtimeclient.CrioName,
	runtimeclient.PodmanName,
}

type RuntimeConfig struct {
	Name       string
	SocketPath string
}

func NewContainerRuntimeClient(runtime *RuntimeConfig) (runtimeclient.ContainerRuntimeClient, error) {
	switch runtime.Name {
	case runtimeclient.DockerName:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_DOCKER_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = envsp
		}
		return docker.NewDockerClient(socketPath)
	case runtimeclient.ContainerdName:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_CONTAINERD_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = envsp
		}
		return containerd.NewContainerdClient(socketPath)
	case runtimeclient.CrioName:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_CRIO_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = envsp
		}
		return crio.NewCrioClient(socketPath)
	case runtimeclient.PodmanName:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_PODMAN_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = envsp
		}
		return podman.NewPodmanClient(socketPath), nil
	default:
		return nil, fmt.Errorf("unknown container runtime: %s (available %s)",
			runtime, strings.Join(AvailableRuntimes, ", "))
	}
}

func getNamespaceInode(pid int, nsType string) (uint64, error) {
	fileinfo, err := os.Stat(filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns", nsType))
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

func GetMntNs(pid int) (uint64, error) {
	return getNamespaceInode(pid, "mnt")
}

func GetNetNs(pid int) (uint64, error) {
	return getNamespaceInode(pid, "net")
}

func ParseOCIState(stateBuf []byte) (id string, pid int, err error) {
	ociState := &ocispec.State{}
	err = json.Unmarshal(stateBuf, ociState)
	if err != nil {
		// Some versions of runc produce an invalid json...
		// As a workaround, make it valid by trimming the invalid parts
		fix := regexp.MustCompile(`(?ms)^(.*),"annotations":.*$`)
		matches := fix.FindStringSubmatch(string(stateBuf))
		if len(matches) != 2 {
			err = fmt.Errorf("cannot parse OCI state: matches=%+v\n %w\n%s", matches, err, string(stateBuf))
			return
		}
		err = json.Unmarshal([]byte(matches[1]+"}"), ociState)
		if err != nil {
			err = fmt.Errorf("cannot parse OCI state: %w\n%s", err, string(stateBuf))
			return
		}
	}
	id = ociState.ID
	pid = ociState.Pid
	return
}
