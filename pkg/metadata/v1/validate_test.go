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

package metadatav1

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func TestValidate(t *testing.T) {
	type testCase struct {
		objectPath        string
		metadata          *GadgetMetadata
		expectedErrString string
	}

	tests := map[string]testCase{
		"missing_name": {
			objectPath:        "../../../testdata/validate_metadata1.o",
			metadata:          &GadgetMetadata{},
			expectedErrString: "gadget name is required",
		},
		"tracers_missing_map_name": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						StructName: "event",
					},
				},
			},
			expectedErrString: "missing mapName",
		},
		"tracers_missing_struct_name": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName: "events",
					},
				},
			},
			expectedErrString: "missing structName",
		},
		"tracers_references_unknown_struct": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Tracers: map[string]Tracer{
					"foo": {
						MapName:    "events",
						StructName: "nonexistent",
					},
				},
			},
			expectedErrString: "referencing unknown struct",
		},
		"tracers_map_not_found": {
			objectPath: "../../../testdata/validate_metadata1.o",
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
			objectPath: "../../../testdata/validate_metadata1.o",
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
		"tracers_map_without_btf": {
			objectPath: "../../../testdata/validate_metadata1.o",
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
		},
		"tracers_good": {
			objectPath: "../../../testdata/validate_metadata1.o",
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
		"toppers_bad_map_type": {
			objectPath: "../../../testdata/validate_metadata_topper.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Toppers: map[string]Topper{
					"foo": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"events\" has a wrong type, expected: hash",
		},
		"toppers_bad_structure_name": {
			objectPath: "../../../testdata/validate_metadata_topper.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Toppers: map[string]Topper{
					"foo": {
						MapName:    "myhashmap",
						StructName: "event2",
					},
				},
				Structs: map[string]Struct{
					"event2": {},
				},
			},
			expectedErrString: "map \"myhashmap\" value name is \"event\", expected \"event2\"",
		},
		"toppers_wrong_value_type": {
			objectPath: "../../../testdata/validate_metadata_topper.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Toppers: map[string]Topper{
					"foo": {
						MapName:    "hash_wrong_value_map",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"hash_wrong_value_map\" value is \"__u32\", expected \"struct\"",
		},
		"toppers_without_btf": {
			objectPath: "../../../testdata/validate_metadata_topper.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Toppers: map[string]Topper{
					"foo": {
						MapName:    "hash_without_btf",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"hash_without_btf\" does not have BTF information for its values",
		},
		"toppers_good": {
			objectPath: "../../../testdata/validate_metadata_topper.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Toppers: map[string]Topper{
					"foo": {
						MapName:    "myhashmap",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
		},
		"structs_nonexistent": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Structs: map[string]Struct{
					"nonexistent": {},
				},
			},
			expectedErrString: "looking for struct \"nonexistent\" in eBPF object",
		},
		"structs_field_nonexistent": {
			objectPath: "../../../testdata/validate_metadata1.o",
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
			objectPath: "../../../testdata/validate_metadata1.o",
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
		"param_nonexistent": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]EBPFParam{
					"bar": {},
				},
			},
			expectedErrString: "variable \"bar\" not found in eBPF object: type name bar: not found",
		},
		"param_nokey": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]EBPFParam{
					"bar": {},
				},
			},
			expectedErrString: "param \"bar\" has an empty key",
		},
		"param_good": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]EBPFParam{
					"param": {
						ParamDesc: params.ParamDesc{
							Key: "param",
						},
					},
				},
			},
		},
		"param2_not_volatile": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]EBPFParam{
					"param2": {},
				},
			},
			expectedErrString: "\"param2\" is not volatile",
		},
		"param3_not_const": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]EBPFParam{
					"param3": {},
				},
			},
			expectedErrString: "\"param3\" is not const",
		},
		"snapshotters_missing_struct_name": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Snapshotters: map[string]Snapshotter{
					"foo": {},
				},
			},
			expectedErrString: "is missing structName",
		},
		"snapshotters_good": {
			objectPath: "../../../testdata/validate_metadata1.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				Snapshotters: map[string]Snapshotter{
					"foo": {
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {},
				},
			},
		},
		"sched_cls": {
			objectPath: "../../../testdata/validate_metadata_sched_cls.o",
			metadata: &GadgetMetadata{
				Name: "foo",
				GadgetParams: map[string]params.ParamDesc{
					"iface": {
						Key: "iface",
					},
				},
			},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			spec, err := ebpf.LoadCollectionSpec(test.objectPath)
			require.NoError(t, err)

			err = test.metadata.Validate(spec)
			if test.expectedErrString == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.expectedErrString)
			}
		})
	}
}
