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

// Package files handles locally stored gadget configurations.
package files

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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence"
)

var GadgetFilePath = "/var/lib/ig"

type FileStore struct {
	persistenceMgr *persistence.Manager
}

func New(mgr *persistence.Manager) (*FileStore, error) {
	fs := &FileStore{
		persistenceMgr: mgr,
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

	gadgets, err := s.getGadgets()
	if err != nil {
		return fmt.Errorf("reading existing gadgets: %w", err)
	}

	for _, gadget := range gadgets {
		log.Infof("loading gadget instance %q", gadget.PersistentGadget.Id)
		s.persistenceMgr.RunGadget(gadget.PersistentGadget.Id, gadget.PersistentGadget.GadgetInfo)
	}
	return nil
}

// loadGadgetFile loads a gadget configuration from a file
func loadGadgetFile(filename string) (*api.InstallPersistentGadgetRequest, error) {
	// TODO: do we need to sanitize?
	blob, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", filename, err)
	}
	gadget := &api.InstallPersistentGadgetRequest{}
	err = protojson.Unmarshal(blob, gadget)
	if err != nil {
		return nil, fmt.Errorf("unmarshal gadget info for file %q: %w", filename, err)
	}
	return gadget, nil
}

// getGadgets returns a list of all installed gadget configurations
func (s *FileStore) getGadgets() ([]*api.InstallPersistentGadgetRequest, error) {
	files, err := os.ReadDir(GadgetFilePath)
	if err != nil {
		return nil, fmt.Errorf("reading gadgets: %w", err)
	}

	res := make([]*api.InstallPersistentGadgetRequest, 0)
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

func (s *FileStore) InstallPersistentGadget(ctx context.Context, req *api.InstallPersistentGadgetRequest) (*api.InstallPersistentGadgetResponse, error) {
	idBytes := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, idBytes)
	if err != nil {
		return nil, fmt.Errorf("could not build gadget id")
	}
	id := hex.EncodeToString(idBytes)
	req.PersistentGadget.Id = id

	if req.PersistentGadget.Name == "" {
		req.PersistentGadget.Name = namesgenerator.GetRandomName(0)
	}

	// Store to gadget file
	gadgetBlob, _ := protojson.Marshal(req)
	filename := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", id))
	err = os.WriteFile(filename, gadgetBlob, 0o644)
	if err != nil {
		return nil, fmt.Errorf("storing gadget information: %w", err)
	}

	log.Debugf("installing new gadget %q", id)
	s.persistenceMgr.RunGadget(req.PersistentGadget.Id, req.PersistentGadget.GadgetInfo)
	return &api.InstallPersistentGadgetResponse{
		Result:           0,
		PersistentGadget: req.PersistentGadget,
	}, nil
}

func (s *FileStore) ListPersistentGadgets(ctx context.Context, request *api.ListPersistentGadgetRequest) (*api.ListPersistentGadgetResponse, error) {
	gadgets, err := s.getGadgets()
	if err != nil {
		return nil, fmt.Errorf("loading gadgets: %w", err)
	}
	persistentGadgets := make([]*api.PersistentGadget, 0, len(gadgets))
	for _, gadget := range gadgets {
		persistentGadgets = append(persistentGadgets, gadget.PersistentGadget)
	}
	return &api.ListPersistentGadgetResponse{PersistentGadgets: persistentGadgets}, nil
}

func (s *FileStore) GetPersistentGadget(ctx context.Context, req *api.PersistentGadgetId) (*api.PersistentGadget, error) {
	path := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", req.Id))
	gadget, err := loadGadgetFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading gadget: %w", err)
	}
	return gadget.PersistentGadget, nil
}

func (s *FileStore) RemovePersistentGadget(ctx context.Context, request *api.PersistentGadgetId) (*api.StatusResponse, error) {
	path := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", request.Id))
	_, err := loadGadgetFile(path)
	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}

	log.Debugf("removing gadget %q", request.Id)
	err = os.Remove(path)
	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	return &api.StatusResponse{Result: 0}, nil
}

func (s *FileStore) StopPersistentGadget(ctx context.Context, request *api.PersistentGadgetId) (*api.StatusResponse, error) {
	return &api.StatusResponse{Result: 0}, nil
}
