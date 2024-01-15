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

package oci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitIGDomain(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		name              string
		expectedDomain    string
		expectedRemainder string
	}

	tests := map[string]testDefinition{
		"no_domain_and_remainder": {
			name:              "trace_exec",
			expectedDomain:    defaultDomain,
			expectedRemainder: officialRepoPrefix + "trace_exec",
		},
		"no_domain_and_remainder_with_tag": {
			name:              "trace_exec:v0.42.0",
			expectedDomain:    defaultDomain,
			expectedRemainder: officialRepoPrefix + "trace_exec:v0.42.0",
		},
		"no_domain": {
			name:              "xyz/gadget/trace_exec",
			expectedDomain:    defaultDomain,
			expectedRemainder: "xyz/gadget/trace_exec",
		},
		"full": {
			name:              "foobar.baz/xyz/gadget/trace_exec",
			expectedDomain:    "foobar.baz",
			expectedRemainder: "xyz/gadget/trace_exec",
		},
		"full_with_port": {
			name:              "foobar.baz:443/xyz/gadget/trace_exec",
			expectedDomain:    "foobar.baz:443",
			expectedRemainder: "xyz/gadget/trace_exec",
		},
		"full_with_port_with_tag": {
			name:              "foobar.baz:443/xyz/gadget/trace_exec:v0.42.0",
			expectedDomain:    "foobar.baz:443",
			expectedRemainder: "xyz/gadget/trace_exec:v0.42.0",
		},
		"localhost": {
			name:              "localhost/trace_exec",
			expectedDomain:    "localhost",
			expectedRemainder: "trace_exec",
		},
		"localhost_with_long_remainder": {
			name:              "localhost/a/b/c/e/d/g/r/trace_exec",
			expectedDomain:    "localhost",
			expectedRemainder: "a/b/c/e/d/g/r/trace_exec",
		},
		"localhost_with_port": {
			name:              "localhost:5000/trace_exec",
			expectedDomain:    "localhost:5000",
			expectedRemainder: "trace_exec",
		},
		"localhost_with_port_with_tag": {
			name:              "localhost:5000/trace_exec:v1.0.3",
			expectedDomain:    "localhost:5000",
			expectedRemainder: "trace_exec:v1.0.3",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actualDomain, actualRemainder := splitIGDomain(test.name)
			assert.Equal(t, test.expectedDomain, actualDomain)
			assert.Equal(t, test.expectedRemainder, actualRemainder)
		})
	}
}

func TestNormalizeImage(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image         string
		imageExpected string
		err           bool
	}

	tests := map[string]testDefinition{
		"empty": {
			image: "",
			err:   true,
		},
		"badtag": {
			image: "inspektor-gadget/ig:~½¬",
			err:   true,
		},
		"image": {
			image:         "ig",
			imageExpected: "ghcr.io/inspektor-gadget/gadget/ig:latest",
		},
		"image_and_tag": {
			image:         "ig:latest",
			imageExpected: "ghcr.io/inspektor-gadget/gadget/ig:latest",
		},
		"image_and_tag_2": {
			image:         "ig:latestttt",
			imageExpected: "ghcr.io/inspektor-gadget/gadget/ig:latestttt",
		},
		"host_image_and_tag": {
			image:         "inspektor-gadget/ig:foobar",
			imageExpected: "ghcr.io/inspektor-gadget/ig:foobar",
		},
		"schema_host_image_and_tag": {
			image: "https://inspektor-gadget/ig:baz",
			err:   true,
		},
		"host_port_image_and_tag": {
			image:         "ghcr.io:443/inspektor-gadget/ig:baz",
			imageExpected: "ghcr.io:443/inspektor-gadget/ig:baz",
		},
		"schema_host_port_image_and_tag": {
			image: "https://ghcr.io:443/inspektor-gadget/ig:latest",
			err:   true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			imageRef, err := normalizeImageName(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.imageExpected, imageRef.String())
		})
	}
}

func TestGetHostString(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image string
		host  string
		err   bool
	}

	tests := map[string]testDefinition{
		"empty": {
			image: "",
			err:   true,
		},
		"badtag": {
			image: "inspektor-gadget/ig:~½¬",
			err:   true,
		},
		"image": {
			image: "ig",
			host:  "",
		},
		"host": {
			image: "ghcr.io",
			host:  "",
		},
		"host_image_and_tag": {
			image: "inspektor-gadget/ig:latest",
			host:  "inspektor-gadget",
		},
		"schema_host_image_and_tag": {
			image: "https://inspektor-gadget/ig:latest",
			err:   true,
		},
		"host_port_image_and_tag": {
			image: "ghcr.io:443/inspektor-gadget/ig:latest",
			host:  "ghcr.io:443",
		},
		"schema_host_port_image_and_tag": {
			image: "https://ghcr.io:443/inspektor-gadget/ig:latest",
			err:   true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			host, err := getHostString(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.host, host)
		})
	}
}
