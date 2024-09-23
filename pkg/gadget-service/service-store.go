// Copyright 2024 The Inspektor Gadget authors
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

package gadgetservice

import (
	"context"
	"fmt"

	"github.com/moby/moby/pkg/namesgenerator"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (s *Service) CreateGadgetInstance(ctx context.Context, request *api.CreateGadgetInstanceRequest) (*api.CreateGadgetInstanceResponse, error) {
	// Create random ID if not set by the client
	if request.GadgetInstance.Id == "" {
		var err error
		request.GadgetInstance.Id, err = api.NewInstanceID()
		if err != nil {
			return nil, fmt.Errorf("generating random id: %w", err)
		}
	} else {
		if !api.IsValidInstanceID(request.GadgetInstance.Id) {
			return nil, fmt.Errorf("invalid gadget instance id: %s", request.GadgetInstance.Id)
		}
	}
	// Create random name if not set by the client
	if request.GadgetInstance.Name == "" {
		request.GadgetInstance.Name = namesgenerator.GetRandomName(0)
	} else if !api.IsValidInstanceName(request.GadgetInstance.Name) {
		return nil, fmt.Errorf("invalid gadget instance name: %s", request.GadgetInstance.Name)
	}
	return s.store.CreateGadgetInstance(ctx, request)
}

func (s *Service) ListGadgetInstances(ctx context.Context, request *api.ListGadgetInstancesRequest) (*api.ListGadgetInstanceResponse, error) {
	return s.store.ListGadgetInstances(ctx, request)
}

func (s *Service) GetGadgetInstance(ctx context.Context, id *api.GadgetInstanceId) (*api.GadgetInstance, error) {
	if !api.IsValidInstanceID(id.Id) {
		return nil, fmt.Errorf("invalid gadget instance id: %s", id.Id)
	}
	return s.store.GetGadgetInstance(ctx, id)
}

func (s *Service) RemoveGadgetInstance(ctx context.Context, id *api.GadgetInstanceId) (*api.StatusResponse, error) {
	if !api.IsValidInstanceID(id.Id) {
		return nil, fmt.Errorf("invalid gadget instance id: %s", id.Id)
	}
	return s.store.RemoveGadgetInstance(ctx, id)
}
