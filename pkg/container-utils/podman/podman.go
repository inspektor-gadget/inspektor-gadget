// Copyright 2023 The Inspektor Gadget authors
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

package podman

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	defaultConnectionTimeout = 2 * time.Second
	containerListAllURL      = "http://d/v4.0.0/libpod/containers/json?all=true"
	containerInspectURL      = "http://d/v4.0.0/libpod/containers/%s/json"
)

type PodmanClient struct {
	client http.Client
}

func NewPodmanClient(socketPath string) runtimeclient.ContainerRuntimeClient {
	if socketPath == "" {
		socketPath = runtimeclient.PodmanDefaultSocketPath
	}

	return &PodmanClient{
		client: http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (conn net.Conn, err error) {
					return net.Dial("unix", socketPath)
				},
			},
			Timeout: defaultConnectionTimeout,
		},
	}
}

func (p *PodmanClient) listContainers(containerID string) ([]*runtimeclient.ContainerData, error) {
	var filters string
	if containerID != "" {
		f, err := json.Marshal(map[string][]string{"id": {containerID}})
		if err != nil {
			return nil, fmt.Errorf("setting up filters: %w", err)
		}
		filters = "&filters=" + url.QueryEscape(string(f))
	}

	resp, err := p.client.Get(containerListAllURL + filters)
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing containers via rest api: %s", resp.Status)
	}

	var containers []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		State string   `json:"State"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decoding containers: %w", err)
	}

	ret := make([]*runtimeclient.ContainerData, len(containers))
	for i, c := range containers {
		ret[i] = &runtimeclient.ContainerData{
			ID:      c.ID,
			Name:    c.Names[0],
			State:   containerStatusStateToRuntimeClientState(c.State),
			Runtime: runtimeclient.PodmanName,
		}
	}
	return ret, nil
}

func (p *PodmanClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	return p.listContainers("")
}

func (p *PodmanClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	containers, err := p.listContainers(containerID)
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, fmt.Errorf("container %q not found", containerID)
	}
	if len(containers) > 1 {
		log.Warnf("PodmanClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(containers), containerID, containers)
	}
	return containers[0], nil
}

func (p *PodmanClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	resp, err := p.client.Get(fmt.Sprintf(containerInspectURL, containerID))
	if err != nil {
		return nil, fmt.Errorf("inspecting container %q: %w", containerID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspecting container via rest api %q: %s", containerID, resp.Status)
	}

	var container struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Status     string `json:"Status"`
			Pid        int    `json:"Pid"`
			CgroupPath string `json:"CgroupPath"`
		} `json:"State"`
	}

	if err = json.NewDecoder(resp.Body).Decode(&container); err != nil {
		return nil, fmt.Errorf("decoding container %q: %w", containerID, err)
	}

	return &runtimeclient.ContainerDetailsData{
		ContainerData: runtimeclient.ContainerData{
			ID:      container.ID,
			Name:    container.Name,
			State:   containerStatusStateToRuntimeClientState(container.State.Status),
			Runtime: runtimeclient.PodmanName,
		},
		Pid:         container.State.Pid,
		CgroupsPath: container.State.CgroupPath,
	}, nil
}

func (p *PodmanClient) Close() error {
	return nil
}

func containerStatusStateToRuntimeClientState(containerState string) string {
	switch containerState {
	case "created":
		return runtimeclient.StateCreated
	case "running":
		return runtimeclient.StateRunning
	case "exited":
		return runtimeclient.StateExited
	case "dead":
		return runtimeclient.StateExited
	default:
		return runtimeclient.StateUnknown
	}
}
