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

package filestore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/moby/pkg/namesgenerator"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
)

var GadgetFilePath = "/var/lib/ig"

type FileStore struct {
	api.GadgetInstanceManagerServer
	instanceMgr *instancemanager.Manager
}

func New(mgr *instancemanager.Manager) (*FileStore, error) {
	fs := &FileStore{
		instanceMgr: mgr,
	}
	err := fs.init()
	if err != nil {
		return nil, err
	}
	return fs, nil
}

// init scans GadgetFilePath for existing gadget configurations and runs them.
func (s *FileStore) init() error {
	// Load & Apply
	err := os.MkdirAll(GadgetFilePath, 0o744)
	if err != nil && errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating directory %q: %w", GadgetFilePath, err)
	}

	return nil
}

// loadGadgetFile loads a gadget configuration from a file
func loadGadgetFile(filename string) (*api.InstallGadgetInstanceRequest, error) {
	// TODO: do we need to sanitize?
	blob, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", filename, err)
	}
	gadget := &api.InstallGadgetInstanceRequest{}
	err = protojson.Unmarshal(blob, gadget)
	if err != nil {
		return nil, fmt.Errorf("unmarshal gadget info for file %q: %w", filename, err)
	}
	return gadget, nil
}

// getGadgets returns a list of all installed gadget configurations
func (s *FileStore) getGadgets() ([]*api.InstallGadgetInstanceRequest, error) {
	files, err := os.ReadDir(GadgetFilePath)
	if err != nil {
		return nil, fmt.Errorf("reading gadgets: %w", err)
	}

	res := make([]*api.InstallGadgetInstanceRequest, 0)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".gadget") {
			continue
		}
		gadget, err := loadGadgetFile(filepath.Join(GadgetFilePath, file.Name()))
		if err != nil {
			log.Warnf("could not read gadget file: %v", err)
			continue
		}
		res = append(res, gadget)
	}
	return res, nil
}

func (s *FileStore) LoadStoredGadgets() error {
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

func (s *FileStore) InstallGadgetInstance(ctx context.Context, req *api.InstallGadgetInstanceRequest) (*api.InstallGadgetInstanceResponse, error) {
	idBytes := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, idBytes)
	if err != nil {
		return nil, errors.New("could not create gadget id")
	}
	id := hex.EncodeToString(idBytes)
	req.GadgetInstance.Id = id

	if req.GadgetInstance.Name == "" {
		req.GadgetInstance.Name = namesgenerator.GetRandomName(0)
	}

	// Store to gadget file
	gadgetBlob, _ := protojson.Marshal(req)
	filename := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", id))
	err = os.WriteFile(filename, gadgetBlob, 0o644)
	if err != nil {
		return nil, fmt.Errorf("storing gadget information: %w", err)
	}

	log.Debugf("installing new gadget %q", id)
	s.instanceMgr.RunGadget(req.GadgetInstance)
	return &api.InstallGadgetInstanceResponse{
		Result:         0,
		GadgetInstance: req.GadgetInstance,
	}, nil
}

func (s *FileStore) ListGadgetInstances(ctx context.Context, request *api.ListGadgetInstancesRequest) (*api.ListGadgetInstanceResponse, error) {
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
	path := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", req.Id))
	gadget, err := loadGadgetFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading gadget: %w", err)
	}
	return gadget.GadgetInstance, nil
}

func (s *FileStore) RemoveGadgetInstance(ctx context.Context, request *api.GadgetInstanceId) (*api.StatusResponse, error) {
	path := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", request.Id))
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

func (s *FileStore) StopGadgetInstance(ctx context.Context, request *api.GadgetInstanceId) (*api.StatusResponse, error) {
	return &api.StatusResponse{Result: 0}, nil
}
