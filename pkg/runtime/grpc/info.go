// Copyright 2023-2024 The Inspektor Gadget authors
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
	"fmt"
	"math"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type Info struct {
	Experimental  bool
	ServerVersion string
}

func (r *Runtime) GetInfo() (*Info, error) {
	if r.info != nil {
		return r.info, nil
	}

	duration := r.globalParams.Get(ParamConnectionTimeout).AsUint()
	if duration > math.MaxInt64 {
		return nil, fmt.Errorf("duration (%d) exceeds math.MaxInt64 (%d)", duration, math.MaxInt64)
	}
	timeout := time.Second * time.Duration(duration)
	ctx, cancelDial := context.WithTimeout(context.Background(), timeout)
	defer cancelDial()

	// use default params for now
	params := r.ParamDescs().ToParams()
	conn, err := r.getConnToRandomTarget(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("dialing random target: %w", err)
	}
	defer conn.Close()
	client := api.NewBuiltInGadgetManagerClient(conn)

	info, err := client.GetInfo(ctx, &api.InfoRequest{Version: "1.0"})
	if err != nil {
		return nil, fmt.Errorf("get info from gadget pod: %w", err)
	}

	r.info = &Info{
		Experimental:  info.Experimental,
		ServerVersion: info.ServerVersion,
	}
	return r.info, nil
}
