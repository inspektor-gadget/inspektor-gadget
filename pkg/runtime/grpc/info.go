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

package grpcruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
)

func loadRemoteDeployInfo() (*deployinfo.DeployInfo, error) {
	ctx, cancelDial := context.WithTimeout(context.Background(), time.Second*ConnectTimeout)
	defer cancelDial()

	// Get a random gadget pod and get the info from there
	pods, err := getGadgetPods(ctx, []string{})
	if err != nil {
		return nil, fmt.Errorf("get gadget pods: %w", err)
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("no valid pods found to get info from")
	}

	pod := pods[0]
	dialOpt := grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
		return NewK8SExecConn(ctx, pod, time.Second*ConnectTimeout)
		// return NewK8SPortForwardConn(ctx, s, time.Second*30)
	})

	conn, err := grpc.DialContext(ctx, "", dialOpt, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("dialing gadget pod on node %q: %w", pod.node, err)
	}
	client := pb.NewGadgetManagerClient(conn)
	defer conn.Close()

	info, err := client.GetInfo(ctx, &pb.InfoRequest{Version: "1.0"})
	if err != nil {
		return nil, fmt.Errorf("get info from gadget pod: %w", err)
	}

	retInfo := &deployinfo.DeployInfo{
		Experimental: info.Experimental,
	}
	err = json.Unmarshal(info.Catalog, &retInfo.Catalog)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling info: %w", err)
	}

	return retInfo, nil
}
