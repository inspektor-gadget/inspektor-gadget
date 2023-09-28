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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// InitDeployInfo loads the locally stored deploy info. If no deploy info is stored locally,
// it will try to fetch it from one of the remotes and store it locally. It will issue warnings on
// failures.
func (r *Runtime) InitDeployInfo() {
	// Initialize info
	info, err := deployinfo.Load()
	if err == nil {
		r.info = info
		return
	}

	info, err = r.loadRemoteDeployInfo()
	if err != nil {
		log.Warnf("could not load gadget info from remote: %v", err)
		return
	}
	r.info = info

	err = deployinfo.Store(info)
	if err != nil {
		log.Warnf("could not store gadget info: %v", err)
	}
}

func (r *Runtime) UpdateDeployInfo() error {
	info, err := r.loadRemoteDeployInfo()
	if err != nil {
		return fmt.Errorf("loading remote gadget info: %w", err)
	}

	return deployinfo.Store(info)
}

func (r *Runtime) loadRemoteDeployInfo() (*deployinfo.DeployInfo, error) {
	ctx, cancelDial := context.WithTimeout(context.Background(), time.Second*ConnectTimeout)
	defer cancelDial()

	// use default params for now
	params := r.ParamDescs().ToParams()
	client, err := r.getClientFromRandomTarget(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("dialing random target: %w", err)
	}

	info, err := client.GetInfo(ctx, &api.InfoRequest{Version: "1.0"})
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
