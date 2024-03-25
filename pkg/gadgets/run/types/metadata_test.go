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

package types

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func TestValidate(t *testing.T) {
	type testCase struct {
		objectPath        string
		metadata          *metadatav1.GadgetMetadata
		expectedErrString string
	}

	tests := map[string]testCase{
		"missing_name": {
			objectPath:        "../../../../testdata/validate_metadata1.o",
			metadata:          &metadatav1.GadgetMetadata{},
			expectedErrString: "gadget name is required",
		},
		"multiple_types": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {},
				},
				Snapshotters: map[string]metadatav1.Snapshotter{
					"bar": {},
				},
			},
			expectedErrString: "gadget can implement only one tracer or snapshotter or topper",
		},
		"tracers_more_than_one": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {},
					"bar": {},
				},
			},
			expectedErrString: "only one tracer is allowed",
		},
		"tracers_missing_map_name": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						StructName: "event",
					},
				},
			},
			expectedErrString: "missing mapName",
		},
		"tracers_missing_struct_name": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						MapName: "events",
					},
				},
			},
			expectedErrString: "missing structName",
		},
		"tracers_references_unknown_struct": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						MapName:    "events",
						StructName: "nonexistent",
					},
				},
			},
			expectedErrString: "referencing unknown struct",
		},
		"tracers_map_not_found": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						MapName:    "nonexistent",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"nonexistent\" not found in eBPF object",
		},
		"tracers_bad_map_type": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						MapName:    "myhashmap",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"myhashmap\" has a wrong type, expected: ringbuf or perf event array",
		},
		"tracers_map_without_btf": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						MapName:    "map_without_btf",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
		},
		"tracers_good": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Tracers: map[string]metadatav1.Tracer{
					"foo": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
		},
		"toppers_more_than_one": {
			objectPath: "../../../../testdata/validate_metadata_topper.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Toppers: map[string]metadatav1.Topper{
					"foo": {},
					"bar": {},
				},
			},
			expectedErrString: "only one topper is allowed",
		},
		"toppers_bad_map_type": {
			objectPath: "../../../../testdata/validate_metadata_topper.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Toppers: map[string]metadatav1.Topper{
					"foo": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"events\" has a wrong type, expected: hash",
		},
		"toppers_bad_structure_name": {
			objectPath: "../../../../testdata/validate_metadata_topper.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Toppers: map[string]metadatav1.Topper{
					"foo": {
						MapName:    "myhashmap",
						StructName: "event2",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event2": {},
				},
			},
			expectedErrString: "map \"myhashmap\" value name is \"event\", expected \"event2\"",
		},
		"toppers_wrong_value_type": {
			objectPath: "../../../../testdata/validate_metadata_topper.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Toppers: map[string]metadatav1.Topper{
					"foo": {
						MapName:    "hash_wrong_value_map",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"hash_wrong_value_map\" value is \"__u32\", expected \"struct\"",
		},
		"toppers_without_btf": {
			objectPath: "../../../../testdata/validate_metadata_topper.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Toppers: map[string]metadatav1.Topper{
					"foo": {
						MapName:    "hash_without_btf",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
			expectedErrString: "map \"hash_without_btf\" does not have BTF information for its values",
		},
		"toppers_good": {
			objectPath: "../../../../testdata/validate_metadata_topper.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Toppers: map[string]metadatav1.Topper{
					"foo": {
						MapName:    "myhashmap",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
		},
		"structs_nonexistent": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Structs: map[string]metadatav1.Struct{
					"nonexistent": {},
				},
			},
			expectedErrString: "looking for struct \"nonexistent\" in eBPF object",
		},
		"structs_field_nonexistent": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
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
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
							{
								Name: "pid",
							},
						},
					},
				},
			},
		},
		"param_nonexistent": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]metadatav1.EBPFParam{
					"bar": {},
				},
			},
			expectedErrString: "variable \"bar\" not found in eBPF object: type name bar: not found",
		},
		"param_nokey": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]metadatav1.EBPFParam{
					"bar": {},
				},
			},
			expectedErrString: "param \"bar\" has an empty key",
		},
		"param_good": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]metadatav1.EBPFParam{
					"param": {
						ParamDesc: params.ParamDesc{
							Key: "param",
						},
					},
				},
			},
		},
		"param2_not_volatile": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]metadatav1.EBPFParam{
					"param2": {},
				},
			},
			expectedErrString: "\"param2\" is not volatile",
		},
		"param3_not_const": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				EBPFParams: map[string]metadatav1.EBPFParam{
					"param3": {},
				},
			},
			expectedErrString: "\"param3\" is not const",
		},
		"snapshotters_more_than_one": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Snapshotters: map[string]metadatav1.Snapshotter{
					"foo": {},
					"bar": {},
				},
			},
			expectedErrString: "only one snapshotter is allowed",
		},
		"snapshotters_missing_struct_name": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Snapshotters: map[string]metadatav1.Snapshotter{
					"foo": {},
				},
			},
			expectedErrString: "is missing structName",
		},
		"snapshotters_good": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Snapshotters: map[string]metadatav1.Snapshotter{
					"foo": {
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {},
				},
			},
		},
		"sched_cls": {
			objectPath: "../../../../testdata/validate_metadata_sched_cls.o",
			metadata: &metadatav1.GadgetMetadata{
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

			err = Validate(test.metadata, spec)
			if test.expectedErrString == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.expectedErrString)
			}
		})
	}
}

func TestPopulate(t *testing.T) {
	expectedTopperMetadataFromScratch := &metadatav1.GadgetMetadata{
		Name:             "TODO: Fill the gadget name",
		Description:      "TODO: Fill the gadget description",
		HomepageURL:      "TODO: Fill the gadget homepage URL",
		DocumentationURL: "TODO: Fill the gadget documentation URL",
		SourceURL:        "TODO: Fill the gadget source code URL",
		Toppers: map[string]metadatav1.Topper{
			"my_topper": {
				MapName:    "events",
				StructName: "event",
			},
		},
		Structs: map[string]metadatav1.Struct{
			"event": {
				Fields: []metadatav1.Field{
					{
						Name:        "pid",
						Description: "TODO: Fill field description",
						Attributes: metadatav1.FieldAttributes{
							Width:     10,
							Alignment: metadatav1.AlignmentLeft,
							Ellipsis:  metadatav1.EllipsisEnd,
						},
					},
					{
						Name:        "comm",
						Description: "TODO: Fill field description",
						Attributes: metadatav1.FieldAttributes{
							Width:     16,
							Alignment: metadatav1.AlignmentLeft,
							Ellipsis:  metadatav1.EllipsisEnd,
						},
					},
					{
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

	type testCase struct {
		initialMetadata   *metadatav1.GadgetMetadata
		expectedMetadata  *metadatav1.GadgetMetadata
		objectPath        string
		expectedErrString string
	}

	tests := map[string]testCase{
		"1_tracer_1_struct_from_scratch": {
			objectPath: "../../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				Tracers: map[string]metadatav1.Tracer{
					"test": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "TODO: Fill field description",
								Attributes: metadatav1.FieldAttributes{
									Width:     10,
									Alignment: metadatav1.AlignmentLeft,
									Ellipsis:  metadatav1.EllipsisEnd,
								},
							},
							{
								Name:        "comm",
								Description: "TODO: Fill field description",
								Attributes: metadatav1.FieldAttributes{
									Width:     16,
									Alignment: metadatav1.AlignmentLeft,
									Ellipsis:  metadatav1.EllipsisEnd,
								},
							},
							{
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
			},
		},
		"tracer_add_missing_field": {
			objectPath: "../../../../testdata/populate_metadata_tracer_add_missing_field.o",
			initialMetadata: &metadatav1.GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				Tracers: map[string]metadatav1.Tracer{
					"test": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						// Set desc and some attributes to be sure they aren't overwritten
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "foo-pid",
								Attributes: metadatav1.FieldAttributes{
									Width:     4747,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							{
								Name:        "comm",
								Description: "bar-comm",
								Attributes: metadatav1.FieldAttributes{
									Width:     1313,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							// missing filename field on purpose to check if it's added
						},
					},
				},
			},
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				Tracers: map[string]metadatav1.Tracer{
					"test": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "foo-pid",
								Attributes: metadatav1.FieldAttributes{
									Width:     4747,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							{
								Name:        "comm",
								Description: "bar-comm",
								Attributes: metadatav1.FieldAttributes{
									Width:     1313,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							{
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
			},
		},
		"no_tracers_from_scratch": {
			objectPath: "../../../../testdata/populate_metadata_no_tracers_from_scratch.o",
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
			},
		},
		"tracer_wrong_map_type": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_wrong_map_type.o",
			expectedErrString: "map \"events\" has a wrong type, expected: ringbuf or perf event array",
		},
		"tracer_non_existing_structure": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_non_existing_structure.o",
			expectedErrString: "finding struct \"non_existing_type\" in eBPF object",
		},
		"tracer_map_without_btf": {
			objectPath: "../../../../testdata/populate_metadata_tracer_map_without_btf.o",
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				Tracers: map[string]metadatav1.Tracer{
					"test": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "TODO: Fill field description",
								Attributes: metadatav1.FieldAttributes{
									Width:     10,
									Alignment: metadatav1.AlignmentLeft,
									Ellipsis:  metadatav1.EllipsisEnd,
								},
							},
							{
								Name:        "comm",
								Description: "TODO: Fill field description",
								Attributes: metadatav1.FieldAttributes{
									Width:     16,
									Alignment: metadatav1.AlignmentLeft,
									Ellipsis:  metadatav1.EllipsisEnd,
								},
							},
							{
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
			},
		},
		"param_populate_from_scratch": {
			objectPath: "../../../../testdata/populate_metadata_1_param_from_scratch.o",
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				EBPFParams: map[string]metadatav1.EBPFParam{
					// This also makes sure that param2 won't get picked up
					// since GADGET_PARAM(param2) is missing
					"param": {
						ParamDesc: params.ParamDesc{
							Key:         "param",
							Description: "TODO: Fill parameter description",
						},
					},
				},
			},
		},
		"param_dont_modify_values": {
			objectPath: "../../../../testdata/populate_metadata_1_param_from_scratch.o",
			initialMetadata: &metadatav1.GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				EBPFParams: map[string]metadatav1.EBPFParam{
					"param": {
						// Set desc and some attributes to be sure they aren't overwritten
						ParamDesc: params.ParamDesc{
							Key:          "my-param-key",
							Description:  "This is my awesome parameter",
							DefaultValue: "42",
						},
					},
				},
			},
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				EBPFParams: map[string]metadatav1.EBPFParam{
					// This also makes sure that param2 won't get picked up
					// since GADGET_PARAM(param2) is missing
					"param": {
						// Check if desc and the other attributes aren't overwritten
						ParamDesc: params.ParamDesc{
							Key:          "my-param-key",
							Description:  "This is my awesome parameter",
							DefaultValue: "42",
						},
					},
				},
			},
		},
		"snapshotter_struct": {
			objectPath: "../../../../testdata/populate_metadata_snapshotter_struct.o",
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				Snapshotters: map[string]metadatav1.Snapshotter{
					"events": {
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "TODO: Fill field description",
								Attributes: metadatav1.FieldAttributes{
									Width:     10,
									Alignment: metadatav1.AlignmentLeft,
									Ellipsis:  metadatav1.EllipsisEnd,
								},
							},
							{
								Name:        "comm",
								Description: "TODO: Fill field description",
								Attributes: metadatav1.FieldAttributes{
									Width:     16,
									Alignment: metadatav1.AlignmentLeft,
									Ellipsis:  metadatav1.EllipsisEnd,
								},
							},
							{
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
			},
		},
		"tracer_non_existing_map": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_non_existing_map.o",
			expectedErrString: "map \"non_existing_map\" not found in eBPF object",
		},
		"tracer_bad_tracer_info": {
			objectPath:        "../../../../testdata/populate_metadata_tracer_bad_tracer_info.o",
			expectedErrString: "invalid tracer info",
		},
		"1_topper_1_struct_from_scratch": {
			objectPath:       "../../../../testdata/populate_metadata_1_topper_1_struct_from_scratch.o",
			expectedMetadata: expectedTopperMetadataFromScratch,
		},
		"topper_multi_definition": {
			objectPath:       "../../../../testdata/populate_metadata_topper_multi_definition.o",
			expectedMetadata: expectedTopperMetadataFromScratch,
		},
		"topper_add_missing_field": {
			objectPath: "../../../../testdata/populate_metadata_topper_add_missing_field.o",
			initialMetadata: &metadatav1.GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Toppers: map[string]metadatav1.Topper{
					"my_topper": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						// Set desc and some attributes to be sure they aren't overwritten
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "foo-pid",
								Attributes: metadatav1.FieldAttributes{
									Width:     4747,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							{
								Name:        "comm",
								Description: "bar-comm",
								Attributes: metadatav1.FieldAttributes{
									Width:     1313,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							// missing filename field on purpose to check if it's added
						},
					},
				},
			},
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Toppers: map[string]metadatav1.Topper{
					"my_topper": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]metadatav1.Struct{
					"event": {
						Fields: []metadatav1.Field{
							{
								Name:        "pid",
								Description: "foo-pid",
								Attributes: metadatav1.FieldAttributes{
									Width:     4747,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							{
								Name:        "comm",
								Description: "bar-comm",
								Attributes: metadatav1.FieldAttributes{
									Width:     1313,
									Alignment: metadatav1.AlignmentRight,
									Ellipsis:  metadatav1.EllipsisStart,
								},
							},
							{
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
			},
		},
		"topper_invalid_struct_name": {
			objectPath: "../../../../testdata/populate_metadata_1_topper_1_struct_from_scratch.o",
			initialMetadata: &metadatav1.GadgetMetadata{
				Name:        "foo",
				Description: "bar",
				Toppers: map[string]metadatav1.Topper{
					"my_topper": {
						MapName:    "events",
						StructName: "event2",
					},
				},
			},
			expectedErrString: "map \"events\" value name is \"event\", expected \"event2\"",
		},
		"topper_non_existing_map": {
			objectPath:        "../../../../testdata/populate_metadata_topper_non_existing_map.o",
			expectedErrString: "map \"non_existing_map\" not found in eBPF object",
		},
		"topper_invalid_info": {
			objectPath:        "../../../../testdata/populate_metadata_topper_bad_topper_info.o",
			expectedErrString: "invalid topper info: \"name___map___bad\"",
		},
		"topper_wrong_map_type": {
			objectPath:        "../../../../testdata/populate_metadata_topper_wrong_map_type.o",
			expectedErrString: "map \"events\" has a wrong type, expected: hash",
		},
		"topper_map_without_btf": {
			objectPath:        "../../../../testdata/populate_metadata_topper_map_without_btf.o",
			expectedErrString: "map \"events\" does not have BTF information for its values",
		},
		"topper_wrong_map_value_type": {
			objectPath:        "../../../../testdata/populate_metadata_topper_wrong_map_value_type.o",
			expectedErrString: "map \"events\" value is \"__u32\", expected \"struct\"",
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
				metadata = &metadatav1.GadgetMetadata{}
			}

			err = Populate(metadata, spec)
			if test.expectedErrString != "" {
				require.ErrorContains(t, err, test.expectedErrString)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expectedMetadata, metadata)
		})
	}
}
