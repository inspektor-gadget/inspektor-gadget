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

package ebpfoperator

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	// TODO: Define GadgetMetadata in metadatav1
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
)

type testCase struct {
	metadata   *runTypes.GadgetMetadata
	objectPath string

	expectedTracers map[string]*Tracer
	initialTracers  map[string]*Tracer

	expectedStructs map[string]*Struct
	initialStructs  map[string]*Struct

	expectedSnapshotters map[string]*Snapshotter
	initialSnapshotters  map[string]*Snapshotter

	expectedErrString string
}

func newTestInstance(test *testCase) (*ebpfInstance, error) {
	// Preallocate maps as done in InstantiateImageOperator()
	tracers := make(map[string]*Tracer)
	if test.initialTracers != nil {
		tracers = test.initialTracers
	}
	if test.expectedTracers == nil {
		test.expectedTracers = make(map[string]*Tracer)
	}

	// Preallocate maps as done in InstantiateImageOperator()
	structs := make(map[string]*Struct)
	if test.initialStructs != nil {
		structs = test.initialStructs
	}
	if test.expectedStructs == nil {
		test.expectedStructs = make(map[string]*Struct)
	}

	// Preallocate maps as done in InstantiateImageOperator()
	snapshotters := make(map[string]*Snapshotter)
	if test.initialSnapshotters != nil {
		snapshotters = test.initialSnapshotters
	}
	if test.expectedSnapshotters == nil {
		test.expectedSnapshotters = make(map[string]*Snapshotter)
	}

	// config is mandatory for the populateTracer() function
	config := viper.New()
	config.SetConfigType("yaml")
	if test.metadata != nil {
		metadata, err := yaml.Marshal(test.metadata)
		if err != nil {
			return nil, fmt.Errorf("marshalling initial metadata: %w", err)
		}

		err = config.ReadConfig(bytes.NewReader(metadata))
		if err != nil {
			return nil, fmt.Errorf("unmarshalling as config initial metadata: %w", err)
		}
	}

	// Load the eBPF test object
	spec, err := ebpf.LoadCollectionSpec(test.objectPath)
	if err != nil {
		return nil, fmt.Errorf("loading collection spec: %w", err)
	}

	// logger is mandatory for the populateTracer() function
	logger := log.StandardLogger()
	// Set the logger level to debug to see the populateTracer() debug logs
	// logger.SetLevel(log.DebugLevel)

	return &ebpfInstance{
		logger:         logger,
		collectionSpec: spec,
		tracers:        tracers,
		snapshotters:   snapshotters,
		structs:        structs,
		config:         config,
	}, nil
}
