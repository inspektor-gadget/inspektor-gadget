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
		"param_nonexistent": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						"bar": {},
					},
				},
			},
			expectedErrString: "variable \"bar\" not found in eBPF object: type name bar: not found",
		},
		"param_nokey": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						"bar": {},
					},
				},
			},
			expectedErrString: "param \"bar\" has an empty key",
		},
		"param_good": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						"param": {
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
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						"param2": {},
					},
				},
			},
			expectedErrString: "\"param2\" is not volatile",
		},
		"param3_not_const": {
			objectPath: "../../../../testdata/validate_metadata1.o",
			metadata: &metadatav1.GadgetMetadata{
				Name: "foo",
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						"param3": {},
					},
				},
			},
			expectedErrString: "\"param3\" is not const",
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
	type testCase struct {
		initialMetadata   *metadatav1.GadgetMetadata
		expectedMetadata  *metadatav1.GadgetMetadata
		objectPath        string
		expectedErrString string
	}

	tests := map[string]testCase{
		"param_populate_from_scratch": {
			objectPath: "../../../../testdata/populate_metadata_1_param_from_scratch.o",
			expectedMetadata: &metadatav1.GadgetMetadata{
				Name:             "TODO: Fill the gadget name",
				Description:      "TODO: Fill the gadget description",
				HomepageURL:      "TODO: Fill the gadget homepage URL",
				DocumentationURL: "TODO: Fill the gadget documentation URL",
				SourceURL:        "TODO: Fill the gadget source code URL",
				DataSources:      map[string]*metadatav1.DataSource{},
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						// This also makes sure that param2 won't get picked up
						// since GADGET_PARAM(param2) is missing
						"param": {
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
				DataSources: map[string]*metadatav1.DataSource{},
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						// Set desc and some attributes to be sure they aren't overwritte
						"param": {
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
				DataSources: map[string]*metadatav1.DataSource{},
				Params: map[string]map[string]params.ParamDesc{
					"ebpf": {
						// This also makes sure that param2 won't get picked up
						// since GADGET_PARAM(param2) is missing
						"param": {
							Key:          "my-param-key",
							Description:  "This is my awesome parameter",
							DefaultValue: "42",
						},
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
