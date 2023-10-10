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
