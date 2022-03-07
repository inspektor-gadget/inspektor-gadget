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

package crio

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	DefaultSocketPath = "/run/crio/crio.sock"
	DefaultTimeout    = 2 * time.Second
)

type CrioClient struct {
	conn   *grpc.ClientConn
	client pb.RuntimeServiceClient
}

func NewCrioClient(path string) (*CrioClient, error) {
	conn, err := grpc.Dial(
		path,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", path, DefaultTimeout)
		}),
	)
	if err != nil {
		return nil, err
	}

	client := pb.NewRuntimeServiceClient(conn)
	return &CrioClient{
		conn:   conn,
		client: client,
	}, nil
}

func (c *CrioClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// parseExtraInfo parses the container extra information returned by
// ContainerStatus(). It keeps backward compatibility after the reply format was
// modified in v1.18.0:
// https://github.com/cri-o/cri-o/commit/be8e876cdabec4e055820502fed227aa44971ddc
func parseExtraInfo(extraInfo map[string]string) (int, error) {
	info, ok := extraInfo["info"]
	if !ok {
		// Try with format used before CRI-O v1.18.0
		pidStr, ok := extraInfo["pid"]
		if !ok {
			return -1, fmt.Errorf("container status reply from runtime doesn't contain pid")
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return -1, fmt.Errorf("failed to parse pid %q: %w", pidStr, err)
		}

		return pid, nil
	}

	type InfoContent struct {
		Pid int `json:"pid"`
	}

	var infoContent InfoContent
	err := json.Unmarshal([]byte(info), &infoContent)
	if err != nil {
		return -1, fmt.Errorf("failed extracting pid from container status reply: %w", err)
	}
	if infoContent.Pid == 0 {
		return -1, fmt.Errorf("couldn't extract pid from container status reply: %s", info)
	}

	return infoContent.Pid, nil
}

func (c *CrioClient) PidFromContainerID(containerID string) (int, error) {
	if !strings.HasPrefix(containerID, "cri-o://") {
		return -1, fmt.Errorf("invalid CRI %s, it should be cri-o", containerID)
	}

	containerID = strings.TrimPrefix(containerID, "cri-o://")

	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return -1, err
	}

	return parseExtraInfo(res.Info)
}
