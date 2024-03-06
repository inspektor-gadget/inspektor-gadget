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
	"strings"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/require"

	// TODO: Define GadgetMetadata in metadatav1
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

func TestPopulate(t *testing.T) {
	expectedGoodTracers := map[string]*Tracer{
		"test": {
			Tracer: metadatav1.Tracer{
				MapName:    "events",
				StructName: "event",
			},
		},
	}

	expectedGoodStructs := map[string]*Struct{
		"event": {
			Fields: []*Field{
				{
					Field: metadatav1.Field{
						Name:        "pid",
						Description: "TODO: Fill field description",
						Attributes: metadatav1.FieldAttributes{
							Width:     10,
							Alignment: metadatav1.AlignmentLeft,
							Ellipsis:  metadatav1.EllipsisEnd,
						},
					},
				},
				{
					Field: metadatav1.Field{
						Name:        "comm",
						Description: "TODO: Fill field description",
						Attributes: metadatav1.FieldAttributes{
							Width:     16,
							Alignment: metadatav1.AlignmentLeft,
							Ellipsis:  metadatav1.EllipsisEnd,
						},
					},
				},
				{
					Field: metadatav1.Field{
						Name:        "filename",
						Description: "TODO: Fill field description",
						Attributes: metadatav1.FieldAttributes{
							Width:     16,
							Alignment: metadatav1.AlignmentLeft,
							Ellipsis:  metadatav1.EllipsisEnd,
						},
					},
				},
			},
		},
	}

	tests := map[string]*testCase{
		"wrong_map_type": {
			objectPath:        "../../../testdata/populate_metadata_tracer_wrong_map_type.o",
			expectedErrString: "map \"events\" has a wrong type, expected: ringbuf or perf event array",
		},
		"non_existing_structure": {
			objectPath:        "../../../testdata/populate_metadata_tracer_non_existing_structure.o",
			expectedErrString: "finding struct \"non_existing_type\" in eBPF object",
		},
		"non_existing_map": {
			objectPath:        "../../../testdata/populate_metadata_tracer_non_existing_map.o",
			expectedErrString: "map \"non_existing_map\" not found in eBPF object",
		},
		"bad_tracer_info": {
			objectPath:        "../../../testdata/populate_metadata_tracer_bad_tracer_info.o",
			expectedErrString: "invalid tracer info",
		},
		"metadata_mismatch_map_name": {
			objectPath: "../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			metadata: &runTypes.GadgetMetadata{
				Tracers: map[string]runTypes.Tracer{
					"test": {
						MapName:    "wrong_map_name",
						StructName: "event",
					},
				},
			},
			expectedErrString: "mapName in tracer metadata for \"test___events___event\" does not match metadata",
		},
		"metadata_mismatch_struct_name": {
			objectPath: "../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			metadata: &runTypes.GadgetMetadata{
				Tracers: map[string]runTypes.Tracer{
					"test": {
						MapName:    "events",
						StructName: "wrong_struct_name",
					},
				},
			},
			expectedErrString: "mapName in tracer metadata for \"test___events___event\" does not match metadata",
		},
		"ignore_second_tracer_definition_with_same_name": {
			objectPath:      "../../../testdata/populate_metadata_tracer_multi_definition.o",
			expectedTracers: expectedGoodTracers,
			expectedStructs: expectedGoodStructs,
		},
		"map_without_btf": {
			objectPath:      "../../../testdata/populate_metadata_tracer_map_without_btf.o",
			expectedTracers: expectedGoodTracers,
			expectedStructs: expectedGoodStructs,
		},
		"good_matching_metadata": {
			objectPath: "../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			metadata: &runTypes.GadgetMetadata{
				Tracers: map[string]runTypes.Tracer{
					"test": {
						MapName:    "events",
						StructName: "event",
					},
				},
				// Structs: expectedStructFromScratch, // TODO: This should be a map[string]*metadatav1.Struct
			},
			expectedTracers: expectedGoodTracers,
			expectedStructs: expectedGoodStructs,
		},
		"good_without_metadata": {
			objectPath:      "../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			expectedTracers: expectedGoodTracers,
			expectedStructs: expectedGoodStructs,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			i, err := newTestInstance(test)
			require.NotNil(t, i)
			require.NoError(t, err)

			var result error
			it := i.collectionSpec.Types.Iterate()
			for it.Next() {
				if !strings.HasPrefix(it.Type.TypeName(), tracerInfoPrefix) {
					continue
				}

				err := i.populateTracer(it.Type, strings.TrimPrefix(it.Type.TypeName(), tracerInfoPrefix))
				if err != nil {
					result = multierror.Append(result, err)
				}
			}

			if test.expectedErrString == "" {
				require.NoError(t, result)
			} else {
				require.ErrorContains(t, result, test.expectedErrString)
			}

			require.Equal(t, test.expectedTracers, i.tracers)
			require.Equal(t, test.expectedStructs, i.structs)
		})
	}
}
