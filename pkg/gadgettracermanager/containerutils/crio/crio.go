package crio

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	DEFAULT_SOCKET_PATH = "/run/crio/crio.sock"
	DEFAULT_TIMEOUT     = 2 * time.Second
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
			return net.DialTimeout("unix", path, DEFAULT_TIMEOUT)
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

func (c *CrioClient) PidFromContainerId(containerID string) (int, error) {
	if !strings.HasPrefix(containerID, "cri-o://") {
		return -1, fmt.Errorf("Invalid CRI %s, it should be cri-o", containerID)
	}

	containerID = strings.TrimPrefix(containerID, "cri-o://")

	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	status, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return -1, err
	}

	pidStr, ok := status.Info["pid"]
	if !ok {
		return -1, fmt.Errorf("container status reply from runtime doesn't contain 'pid'")
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return -1, err
	}

	return pid, nil
}
