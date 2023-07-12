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

package gadgetservice

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func (s *Service) InstallPersistentGadget(ctx context.Context, req *api.InstallPersistentGadgetRequest) (*api.InstallPersistentGadgetResponse, error) {
	return s.persistenceMgr.InstallPersistentGadget(ctx, req)
}

func (s *Service) ListPersistentGadgets(ctx context.Context, request *api.ListPersistentGadgetRequest) (*api.ListPersistentGadgetResponse, error) {
	return s.persistenceMgr.ListPersistentGadgets(ctx, request)
}

func (s *Service) RemovePersistentGadget(ctx context.Context, request *api.PersistentGadgetId) (*api.StatusResponse, error) {
	return s.persistenceMgr.RemovePersistentGadget(ctx, request)
}

func (s *Service) AttachToPersistentGadget(req *api.PersistentGadgetId, client api.GadgetManager_AttachToPersistentGadgetServer) error {
	return s.persistenceMgr.AttachToPersistentGadget(req, client)
}

func (s *Service) GetPersistentGadget(ctx context.Context, req *api.PersistentGadgetId) (*api.PersistentGadget, error) {
	return s.persistenceMgr.GetPersistentGadget(ctx, req)
}

func (s *Service) StopPersistentGadget(ctx context.Context, req *api.PersistentGadgetId) (*api.StatusResponse, error) {
	return s.persistenceMgr.StopPersistentGadget(ctx, req)
}
