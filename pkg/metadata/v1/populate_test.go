package metadatav1

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func TestPopulate(t *testing.T) {
	expectedTopperMetadataFromScratch := &GadgetMetadata{
		Name:             "TODO: Fill the gadget name",
		Description:      "TODO: Fill the gadget description",
		HomepageURL:      "TODO: Fill the gadget homepage URL",
		DocumentationURL: "TODO: Fill the gadget documentation URL",
		SourceURL:        "TODO: Fill the gadget source code URL",
		Toppers: map[string]Topper{
			"my_topper": {
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
	}

	type testCase struct {
		initialMetadata   *GadgetMetadata
		expectedMetadata  *GadgetMetadata
		objectPath        string
		expectedErrString string
	}

	tests := map[string]testCase{
		"1_tracer_1_struct_from_scratch": {
			objectPath: "../../../testdata/populate_metadata_1_tracer_1_struct_from_scratch.o",
			expectedMetadata: &GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				Tracers: map[string]Tracer{
					"test": {
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
			objectPath: "../../../testdata/populate_metadata_tracer_add_missing_field.o",
			initialMetadata: &GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				Tracers: map[string]Tracer{
					"test": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {
						// Set desc and some attributes to be sure they aren't overwritten
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
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				Tracers: map[string]Tracer{
					"test": {
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
			objectPath: "../../../testdata/populate_metadata_no_tracers_from_scratch.o",
			expectedMetadata: &GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
			},
		},
		"tracer_wrong_map_type": {
			objectPath:        "../../../testdata/populate_metadata_tracer_wrong_map_type.o",
			expectedErrString: "map \"events\" has a wrong type, expected: ringbuf or perf event array",
		},
		"tracer_non_existing_structure": {
			objectPath:        "../../../testdata/populate_metadata_tracer_non_existing_structure.o",
			expectedErrString: "finding struct \"non_existing_type\" in eBPF object",
		},
		"tracer_map_without_btf": {
			objectPath: "../../../testdata/populate_metadata_tracer_map_without_btf.o",
			expectedMetadata: &GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				Tracers: map[string]Tracer{
					"test": {
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
		"param_populate_from_scratch": {
			objectPath: "../../../testdata/populate_metadata_1_param_from_scratch.o",
			expectedMetadata: &GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				EBPFParams: map[string]EBPFParam{
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
			objectPath: "../../../testdata/populate_metadata_1_param_from_scratch.o",
			initialMetadata: &GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				EBPFParams: map[string]EBPFParam{
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
			expectedMetadata: &GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Annotations: map[string]string{
					"io.inspektor-gadget.test": "test",
				},
				EBPFParams: map[string]EBPFParam{
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
			objectPath: "../../../testdata/populate_metadata_snapshotter_struct.o",
			expectedMetadata: &GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				Snapshotters: map[string]Snapshotter{
					"events": {
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
		"tracer_non_existing_map": {
			objectPath:        "../../../testdata/populate_metadata_tracer_non_existing_map.o",
			expectedErrString: "map \"non_existing_map\" not found in eBPF object",
		},
		"tracer_bad_tracer_info": {
			objectPath:        "../../../testdata/populate_metadata_tracer_bad_tracer_info.o",
			expectedErrString: "invalid tracer info",
		},
		"1_topper_1_struct_from_scratch": {
			objectPath:       "../../../testdata/populate_metadata_1_topper_1_struct_from_scratch.o",
			expectedMetadata: expectedTopperMetadataFromScratch,
		},
		"topper_multi_definition": {
			objectPath:       "../../../testdata/populate_metadata_topper_multi_definition.o",
			expectedMetadata: expectedTopperMetadataFromScratch,
		},
		"topper_add_missing_field": {
			objectPath: "../../../testdata/populate_metadata_topper_add_missing_field.o",
			initialMetadata: &GadgetMetadata{
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Toppers: map[string]Topper{
					"my_topper": {
						MapName:    "events",
						StructName: "event",
					},
				},
				Structs: map[string]Struct{
					"event": {
						// Set desc and some attributes to be sure they aren't overwritten
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
				Name:             "foo",
				Description:      "bar",
				HomepageURL:      "url1",
				DocumentationURL: "url2",
				SourceURL:        "url3",
				Toppers: map[string]Topper{
					"my_topper": {
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
		"topper_invalid_struct_name": {
			objectPath: "../../../testdata/populate_metadata_1_topper_1_struct_from_scratch.o",
			initialMetadata: &GadgetMetadata{
				Name:        "foo",
				Description: "bar",
				Toppers: map[string]Topper{
					"my_topper": {
						MapName:    "events",
						StructName: "event2",
					},
				},
			},
			expectedErrString: "map \"events\" value name is \"event\", expected \"event2\"",
		},
		"topper_non_existing_map": {
			objectPath:        "../../../testdata/populate_metadata_topper_non_existing_map.o",
			expectedErrString: "map \"non_existing_map\" not found in eBPF object",
		},
		"topper_invalid_info": {
			objectPath:        "../../../testdata/populate_metadata_topper_bad_topper_info.o",
			expectedErrString: "invalid topper info: \"name___map___bad\"",
		},
		"topper_wrong_map_type": {
			objectPath:        "../../../testdata/populate_metadata_topper_wrong_map_type.o",
			expectedErrString: "map \"events\" has a wrong type, expected: hash",
		},
		"topper_map_without_btf": {
			objectPath:        "../../../testdata/populate_metadata_topper_map_without_btf.o",
			expectedErrString: "map \"events\" does not have BTF information for its values",
		},
		"topper_wrong_map_value_type": {
			objectPath:        "../../../testdata/populate_metadata_topper_wrong_map_value_type.o",
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
