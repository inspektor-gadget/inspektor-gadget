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
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/crio"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/docker"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/podman"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	nsenter "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/nsenter"
)

var AvailableRuntimes = []string{
	types.RuntimeNameDocker.String(),
	types.RuntimeNameContainerd.String(),
	types.RuntimeNameCrio.String(),
	types.RuntimeNamePodman.String(),
}

var AvailableRuntimeProtocols = []string{
	containerutilsTypes.RuntimeProtocolInternal,
	containerutilsTypes.RuntimeProtocolCRI,
}

func NewContainerRuntimeClient(runtime *containerutilsTypes.RuntimeConfig) (runtimeclient.ContainerRuntimeClient, error) {
	switch runtime.Name {
	case types.RuntimeNameDocker:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_DOCKER_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = filepath.Join(host.HostRoot, envsp)
		}
		return docker.NewDockerClient(socketPath, runtime.RuntimeProtocol)
	case types.RuntimeNameContainerd:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_CONTAINERD_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = filepath.Join(host.HostRoot, envsp)
		}
		return containerd.NewContainerdClient(socketPath, runtime.RuntimeProtocol, &runtime.Extra)
	case types.RuntimeNameCrio:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_CRIO_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = filepath.Join(host.HostRoot, envsp)
		}
		return crio.NewCrioClient(socketPath)
	case types.RuntimeNamePodman:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_PODMAN_SOCKETPATH"); envsp != "" && socketPath == "" {
			socketPath = filepath.Join(host.HostRoot, envsp)
		}
		return podman.NewPodmanClient(socketPath), nil
	default:
		return nil, fmt.Errorf("unknown container runtime: %s (available %s)",
			runtime.Name, strings.Join(AvailableRuntimes, ", "))
	}
}

func getNamespaceInode(pid int, nsType string) (uint64, error) {
	fileinfo, err := os.Stat(filepath.Join(host.HostProcFs, fmt.Sprint(pid), "ns", nsType))
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
			err = fmt.Errorf("parsing OCI state: matches=%+v\n %w\n%s", matches, err, string(stateBuf))
			return
		}
		err = json.Unmarshal([]byte(matches[1]+"}"), ociState)
		if err != nil {
			err = fmt.Errorf("parsing OCI state: %w\n%s", err, string(stateBuf))
			return
		}
	}
	id = ociState.ID
	pid = ociState.Pid
	return
}

// GetIfacePeers returns the networking interfaces on the host side of the container where pid is
// running in.
func GetIfacePeers(pid int) ([]*net.Interface, error) {
	var ifaceLinks []int

	err := nsenter.NetnsEnter(pid, func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("getting links: %w", err)
		}

		for _, link := range links {
			veth, ok := link.(*netlink.Veth)
			if !ok {
				continue
			}

			if veth.Flags&net.FlagUp == 0 {
				continue
			}

			ifaceLink, err := netlink.VethPeerIndex(veth)
			if err != nil {
				return fmt.Errorf("getting veth's pair index: %w", err)
			}

			ifaceLinks = append(ifaceLinks, ifaceLink)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(ifaceLinks) == 0 {
		return nil, fmt.Errorf("no interface found")
	}

	ifacesHost := make([]*net.Interface, 0, len(ifaceLinks))

	err = nsenter.NetnsEnter(1, func() error {
		for _, ifaceLink := range ifaceLinks {
			ifaceHost, err := net.InterfaceByIndex(ifaceLink)
			if err != nil {
				return fmt.Errorf("getting interface by index: %w", err)
			}

			ifacesHost = append(ifacesHost, ifaceHost)
		}
		return nil
	})

	return ifacesHost, err
}
