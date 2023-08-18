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

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRepositoryFromImage(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image      string
		repository string
		err        bool
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
			image:      "ig",
			repository: "ig",
		},
		"image_and_tag": {
			image:      "ig:latest",
			repository: "ig",
		},
		"host": {
			image:      "ghcr.io",
			repository: "ghcr.io",
		},
		"host_image_and_tag": {
			image:      "inspektor-gadget/ig:latest",
			repository: "inspektor-gadget/ig",
		},
		"schema_host_image_and_tag": {
			image: "https://inspektor-gadget/ig:latest",
			err:   true,
		},
		"host_port_image_and_tag": {
			image:      "ghcr.io:443/inspektor-gadget/ig:latest",
			repository: "ghcr.io:443/inspektor-gadget/ig",
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

			repository, err := GetRepositoryFromImage(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.repository, repository)
		})
	}
}

func TestGetTagFromImage(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image string
		tag   string
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
			tag:   "latest",
		},
		"image_and_tag": {
			image: "ig:latest",
			tag:   "latest",
		},
		"image_and_tag_2": {
			image: "ig:latestttt",
			tag:   "latestttt",
		},
		"host": {
			image: "ghcr.io",
			tag:   "latest",
		},
		"host_image_and_tag": {
			image: "inspektor-gadget/ig:foobar",
			tag:   "foobar",
		},
		"schema_host_image_and_tag": {
			image: "https://inspektor-gadget/ig:baz",
			err:   true,
		},
		"host_port_image_and_tag": {
			image: "ghcr.io:443/inspektor-gadget/ig:baz",
			tag:   "baz",
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

			tag, err := GetTagFromImage(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.tag, tag)
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
			imageExpected: "docker.io/library/ig:latest",
		},
		"image_and_tag": {
			image:         "ig:latest",
			imageExpected: "docker.io/library/ig:latest",
		},
		"image_and_tag_2": {
			image:         "ig:latestttt",
			imageExpected: "docker.io/library/ig:latestttt",
		},
		"host_image_and_tag": {
			image:         "inspektor-gadget/ig:foobar",
			imageExpected: "docker.io/inspektor-gadget/ig:foobar",
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

			image, err := NormalizeImage(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.imageExpected, image)
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

			host, err := GetHostString(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.host, host)
		})
	}
}
