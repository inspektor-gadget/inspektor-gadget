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

package types

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	const objectPath = "../../../../testdata/validate_metadata1.o"

	type testCase struct {
		metadata          *GadgetMetadata
		expectedErrString string
	}

	tests := map[string]testCase{
		"missing_name": {
			metadata:          &GadgetMetadata{},
			expectedErrString: "gadget name is required",
		},
		"tracers_more_than_one": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {},
					"bar": {},
				},
			},
			expectedErrString: "only one tracer is allowed",
		},
		"tracers_missing_map_name": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						StructName: "event",
					},
				},
			},
			expectedErrString: "is missing mapName",
		},
		"tracers_missing_struct_name": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName: "events",
					},
				},
			},
			expectedErrString: "is missing structName",
		},
		"tracers_references_unknown_struct": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "events",
						StructName: "nonexistent",
					},
				},
			},
			expectedErrString: "references unknown struct",
		},
		"tracers_map_not_found": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "nonexistent",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"nonexistent\" not found in eBPF object",
		},
		"tracers_bad_map_type": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "myhashmap",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"myhashmap\" has a wrong type, expected: ringbuf or perf event array",
		},
		"tracers_wrong_value_map": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "wrong_value_map",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "value of BPF map \"wrong_value_map\" is not a structure",
		},
		"tracers_map_without_btf": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "map_without_btf",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"map_without_btf\" does not have BTF information its value",
		},
		"tracers_good": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
		},
		"structs_nonexistent": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Structs: map[string]Struct{
					"nonexistent": {},
				},
			},
			expectedErrString: "looking for struct \"nonexistent\" in eBPF object",
		},
		"structs_field_nonexistent": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Structs: map[string]Struct{
					"event": {
						Fields: []Field{
							{
								Name: "nonexistent",
							},
						},
					},
				},
			},
			expectedErrString: "field \"nonexistent\" not found in eBPF struct",
		},
		"structs_good": {
			metadata: &GadgetMetadata{
				Name: "foo",
				Structs: map[string]Struct{
					"event": {
						Fields: []Field{
							{
								Name: "pid",
							},
						},
					},
				},
			},
		},
	}

	// it's fine for now to use the same spec for all tests, hence do this once
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	require.NoError(t, err)

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err = test.metadata.Validate(spec)
			if test.expectedErrString == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.expectedErrString)
			}
		})
	}
}

func TestPopulate(t *testing.T) {
	type testCase struct {
		initialMetadata   *GadgetMetadata
		expectedMetadata  *GadgetMetadata
		objectPath        string
		expectedErrString string
	}

	tests := map[string]testCase{
		"1_tracer_1_struct_from_scratch": {
			objectPath: "../../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			expectedMetadata: &GadgetMetadata{
				Name:        "TODO: Fill the gadget name",
				Description: "TODO: Fill the gadget description",
				Tracers: map[string]Tracer{
					"events": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {
						Fields: []Field{
							{
								Name:        "pid",
								Description: "TODO: Fill field description",
								Attributes: FieldAttributes{
									Width:     10,
									Alignment: AlignmentLeft,
									Ellipsis:  EllipsisEnd,
								},
							},
							{
								Name:        "comm",
								Description: "TODO: Fill field description",
								Attributes: FieldAttributes{
									Width:     16,
									Alignment: AlignmentLeft,
									Ellipsis:  EllipsisEnd,
								},
							},
							{
								Name:        "filename",
								Description: "TODO: Fill field description",
								Attributes: FieldAttributes{
									Width:     16,
									Alignment: AlignmentLeft,
									Ellipsis:  EllipsisEnd,
								},
							},
						},
					},
				},
			},
		},
		"tracer_add_missing_field": {
			objectPath: "../../../../testdata/populate_metadata_tracer_add_missing_field.o",
			initialMetadata: &GadgetMetadata{
				Name:        "foo",
				Description: "bar",
				Tracers: map[string]Tracer{
					"events": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {
						// Set desc and some  attributes to be sure they aren't overwritten
						Fields: []Field{
							{
								Name:        "pid",
								Description: "foo-pid",
								Attributes: FieldAttributes{
									Width:     4747,
									Alignment: AlignmentRight,
									Ellipsis:  EllipsisStart,
								},
							},
							{
								Name:        "comm",
								Description: "bar-comm",
								Attributes: FieldAttributes{
									Width:     1313,
									Alignment: AlignmentRight,
									Ellipsis:  EllipsisStart,
								},
							},
							// missing filename field on purpose to check if it's added
						},
					},
				},
			},
			expectedMetadata: &GadgetMetadata{
				Name:        "foo",
				Description: "bar",
				Tracers: map[string]Tracer{
					"events": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {
						Fields: []Field{
							{
								Name:        "pid",
								Description: "foo-pid",
								Attributes: FieldAttributes{
									Width:     4747,
									Alignment: AlignmentRight,
									Ellipsis:  EllipsisStart,
								},
							},
							{
								Name:        "comm",
								Description: "bar-comm",
								Attributes: FieldAttributes{
									Width:     1313,
									Alignment: AlignmentRight,
									Ellipsis:  EllipsisStart,
								},
							},
							{
								Name:        "filename",
								Description: "TODO: Fill field description",
								Attributes: FieldAttributes{
									Width:     16,
									Alignment: AlignmentLeft,
									Ellipsis:  EllipsisEnd,
								},
							},
						},
					},
				},
			},
		},
		"no_tracers_from_scratch": {
			objectPath: "../../../../testdata/populate_metadata_no_tracers_from_scratch.o",
			expectedMetadata: &GadgetMetadata{
				Name:        "TODO: Fill the gadget name",
				Description: "TODO: Fill the gadget description",
				Tracers:     map[string]Tracer{},
				Structs:     map[string]Struct{},
			},
		},
		"tracer_wrong_map_type": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_wrong_map_type.o",
			expectedErrString: "map \"events\" has a wrong type, expected: ringbuf or perf event array",
		},
		"tracer_wrong_map_value_type": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_wrong_map_value_type.o",
			expectedErrString: "value of BPF map \"events\" is not a structure",
		},
		"tracer_map_without_btf": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_map_without_btf.o",
			expectedErrString: "map \"events\" does not have BTF information its value",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			spec, err := ebpf.LoadCollectionSpec(test.objectPath)
			require.NoError(t, err)

			metadata := test.initialMetadata
			if metadata == nil {
				metadata = &GadgetMetadata{}
			}

			err = metadata.Populate(spec)
			if test.expectedErrString != "" {
				require.ErrorContains(t, err, test.expectedErrString)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expectedMetadata, metadata)
		})
	}
}
