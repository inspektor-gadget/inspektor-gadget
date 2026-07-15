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

	"github.com/inspektor-gadget/inspektor-gadget/internal/namesgenerator"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	kubemanagerpolicy "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/policy"
)

func (s *Service) CreateGadgetInstance(ctx context.Context, request *api.CreateGadgetInstanceRequest) (*api.CreateGadgetInstanceResponse, error) {
	if request.GadgetInstance == nil || request.GadgetInstance.GadgetConfig == nil {
		return nil, fmt.Errorf("missing gadget instance configuration")
	}
	if request.GadgetInstance.GadgetConfig.ParamValues == nil {
		request.GadgetInstance.GadgetConfig.ParamValues = api.ParamValues{}
	}
	if err := kubemanagerpolicy.EnforcePolicyScopeOnParamValues(ctx, request.GadgetInstance.GadgetConfig.ParamValues); err != nil {
		return nil, err
	}

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
	resp, err := s.store.ListGadgetInstances(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("listing gadget instances: %w", err)
	}
	visible := resp.GadgetInstances[:0]
	for _, gi := range resp.GadgetInstances {
		if err := authorizeGadgetInstance(ctx, gi); err != nil {
			continue
		}
		st, err := s.instanceMgr.InstanceState(gi.Id)
		if err != nil {
			return nil, fmt.Errorf("getting instance status for %q: %w", gi.Id, err)
		}
		gi.State = st
		visible = append(visible, gi)
	}
	resp.GadgetInstances = visible
	return resp, nil
}

func (s *Service) GetGadgetInstance(ctx context.Context, id *api.GadgetInstanceId) (*api.GadgetInstance, error) {
	if !api.IsValidInstanceID(id.Id) {
		return nil, fmt.Errorf("invalid gadget instance id: %s", id.Id)
	}
	gi, err := s.store.GetGadgetInstance(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting gadget instance from store: %w", err)
	}
	if err := authorizeGadgetInstance(ctx, gi); err != nil {
		return nil, err
	}
	st, err := s.instanceMgr.InstanceState(gi.Id)
	if err != nil {
		return nil, fmt.Errorf("getting instance status for %q: %w", gi.Id, err)
	}
	gi.State = st
	return gi, nil
}

func (s *Service) RemoveGadgetInstance(ctx context.Context, id *api.GadgetInstanceId) (*api.StatusResponse, error) {
	if !api.IsValidInstanceID(id.Id) {
		return nil, fmt.Errorf("invalid gadget instance id: %s", id.Id)
	}
	gi, err := s.store.GetGadgetInstance(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting gadget instance from store: %w", err)
	}
	if err := authorizeGadgetInstance(ctx, gi); err != nil {
		return nil, err
	}
	return s.store.RemoveGadgetInstance(ctx, id)
}

func authorizeGadgetInstance(ctx context.Context, instance *api.GadgetInstance) error {
	if instance == nil || instance.GadgetConfig == nil {
		return fmt.Errorf("missing gadget instance configuration")
	}
	return kubemanagerpolicy.AuthorizeParamValues(ctx, instance.GadgetConfig.ParamValues)
}
