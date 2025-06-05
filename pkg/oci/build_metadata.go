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

package oci

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

func loadSpec(progContent []byte) (*ebpf.CollectionSpec, error) {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}
	return spec, err
}

// getAnySpec returns the spec for any architecture found. It's used to generate the metadata so we
// don't care about the architecture this file was generated for.
func getAnySpec(opts *BuildGadgetImageOpts) (*ebpf.CollectionSpec, error) {
	var progPath string

	// TODO: we could perform a sanity check to be sure different architectures generate the
	// same metadata, but that's too much for now.
	// We're validating the metadata at runtime, so a possible error will be caught there.
	for _, paths := range opts.ObjectPaths {
		progPath = paths.EBPF
		break
	}

	if progPath == "" {
		return nil, fmt.Errorf("no eBPF object file found: %w", os.ErrNotExist)
	}

	progContent, err := os.ReadFile(progPath)
	if err != nil {
		return nil, fmt.Errorf("reading eBPF object file: %w", err)
	}

	return loadSpec(progContent)
}

func createOrUpdateMetadataFile(ctx context.Context, opts *BuildGadgetImageOpts, spec *ebpf.CollectionSpec, metadata metadatav1.GadgetMetadata, hasMetadataFile bool) error {
	if !hasMetadataFile {
		log.Debug("Metadata file not found, generating it")
	}

	if err := types.Populate(&metadata, spec); err != nil {
		return fmt.Errorf("populating metadata: %w", err)
	}

	marshalled, err := yaml.Marshal(metadata)
	if err != nil {
		return err
	}

	if err := os.WriteFile(opts.MetadataPath, marshalled, 0o644); err != nil {
		return fmt.Errorf("writing metadata file: %w", err)
	}

	// fix owner of created metadata file
	if !hasMetadataFile {
		if err := copyFileOwner(filepath.Dir(opts.MetadataPath), opts.MetadataPath); err != nil {
			log.Warnf("Failed to fix metadata file owner: %v", err)
		}
	}

	return nil
}
