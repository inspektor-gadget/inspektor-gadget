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

package filestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/store"
)

const (
	GadgetBaseDir     = "/var/lib/ig"
	GadgetInstanceDir = "/var/lib/ig/gadgets"
)

type FileStore struct {
	api.GadgetInstanceManagerServer
	instanceMgr *instancemanager.Manager
	mu          sync.Mutex
}

func New(mgr *instancemanager.Manager) (store.Store, error) {
	fs := &FileStore{
		instanceMgr: mgr,
	}
	err := fs.init()
	if err != nil {
		return nil, err
	}
	return fs, nil
}

func (s *FileStore) init() error {
	err := os.MkdirAll(GadgetBaseDir, 0o755)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating directory %q: %w", GadgetBaseDir, err)
	}
	err = os.MkdirAll(GadgetInstanceDir, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating directory %q: %w", GadgetInstanceDir, err)
	}
	return nil
}

// loadGadgetFile loads a gadget configuration from a file
func loadGadgetFile(filename string) (*api.CreateGadgetInstanceRequest, error) {
	// filename is sanitized to contain only hex characters by the instance manager
	blob, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("gadget instance not found at %q", filename)
		}
		return nil, fmt.Errorf("read file %q: %w", filename, err)
	}
	gadget := &api.CreateGadgetInstanceRequest{}
	err = protojson.Unmarshal(blob, gadget)
	if err != nil {
		return nil, fmt.Errorf("unmarshal gadget info for file %q: %w", filename, err)
	}
	return gadget, nil
}

// getGadgets returns a list of all installed gadget configurations
func (s *FileStore) getGadgets() ([]*api.CreateGadgetInstanceRequest, error) {
	files, err := os.ReadDir(GadgetInstanceDir)
	if err != nil {
		return nil, fmt.Errorf("reading gadgets: %w", err)
	}

	res := make([]*api.CreateGadgetInstanceRequest, 0)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".gadget") {
			continue
		}
		gadget, err := loadGadgetFile(filepath.Join(GadgetInstanceDir, file.Name()))
		if err != nil {
			log.Warnf("could not read gadget file: %v", err)
			continue
		}
		res = append(res, gadget)
	}
	return res, nil
}

func (s *FileStore) ResumeStoredGadgets() error {
	gadgets, err := s.getGadgets()
	if err != nil {
		return fmt.Errorf("reading existing gadgets: %w", err)
	}

	for _, gadget := range gadgets {
		log.Infof("loading gadget instance %q", gadget.GadgetInstance.Id)
		s.instanceMgr.RunGadget(gadget.GadgetInstance)
	}
	return nil
}

func (s *FileStore) CreateGadgetInstance(ctx context.Context, req *api.CreateGadgetInstanceRequest) (*api.CreateGadgetInstanceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store to gadget file
	gadgetBlob, _ := protojson.Marshal(req)

	// req.GadgetInstance.Id is sanitized in service-store.go
	filename := filepath.Join(GadgetInstanceDir, fmt.Sprintf("%s.gadget", req.GadgetInstance.Id))

	// check whether a gadget with the given id or name already exists
	gadgets, err := s.getGadgets()
	if err != nil {
		return nil, fmt.Errorf("reading existing gadgets: %w", err)
	}
	for _, gadget := range gadgets {
		if gadget.GadgetInstance.Id == req.GadgetInstance.Id {
			return nil, fmt.Errorf("gadget with id %q already exists", req.GadgetInstance.Id)
		}
		if gadget.GadgetInstance.Name == req.GadgetInstance.Name {
			return nil, fmt.Errorf("gadget with name %q already exists", req.GadgetInstance.Name)
		}
	}

	err = os.WriteFile(filename, gadgetBlob, 0o644)
	if err != nil {
		return nil, fmt.Errorf("storing gadget information: %w", err)
	}

	log.Debugf("installing new gadget %q", req.GadgetInstance.Id)
	s.instanceMgr.RunGadget(req.GadgetInstance)
	return &api.CreateGadgetInstanceResponse{
		Result:         0,
		GadgetInstance: req.GadgetInstance,
	}, nil
}

func (s *FileStore) ListGadgetInstances(ctx context.Context, request *api.ListGadgetInstancesRequest) (*api.ListGadgetInstanceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	gadgets, err := s.getGadgets()
	if err != nil {
		return nil, fmt.Errorf("loading gadgets: %w", err)
	}
	persistentGadgets := make([]*api.GadgetInstance, 0, len(gadgets))
	for _, gadget := range gadgets {
		persistentGadgets = append(persistentGadgets, gadget.GadgetInstance)
	}
	return &api.ListGadgetInstanceResponse{GadgetInstances: persistentGadgets}, nil
}

func (s *FileStore) GetGadgetInstance(ctx context.Context, req *api.GadgetInstanceId) (*api.GadgetInstance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(GadgetInstanceDir, fmt.Sprintf("%s.gadget", req.Id))
	gadget, err := loadGadgetFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading gadget: %w", err)
	}
	return gadget.GadgetInstance, nil
}

func (s *FileStore) RemoveGadgetInstance(ctx context.Context, request *api.GadgetInstanceId) (*api.StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(GadgetInstanceDir, fmt.Sprintf("%s.gadget", request.Id))
	_, err := loadGadgetFile(path)
	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}

	err = s.instanceMgr.RemoveGadget(request.Id)
	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	err = os.Remove(path)
	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	return &api.StatusResponse{Result: 0}, nil
}
