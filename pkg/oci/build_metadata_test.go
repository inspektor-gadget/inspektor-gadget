// Copyright 2026 The Inspektor Gadget authors
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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestCreateOrUpdateMetadataFileWithoutEBPF(t *testing.T) {
	t.Parallel()

	metadataPath := filepath.Join(t.TempDir(), "gadget.yaml")
	err := os.WriteFile(metadataPath, []byte(`name: foo
description: bar
operator:
  ebpf:
    emitstats: true
paramDefaults:
  operator.sort.sort: -runtime
`), 0o644)
	require.NoError(t, err)

	opts := &BuildGadgetImageOpts{
		ObjectPaths: map[string]*ObjectPath{
			ArchAmd64: {},
			ArchArm64: {},
		},
		MetadataPath: metadataPath,
	}

	err = createOrUpdateMetadataFile(context.Background(), opts)
	require.NoError(t, err)

	content, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	metadata := map[string]any{}
	err = yaml.Unmarshal(content, &metadata)
	require.NoError(t, err)

	require.Equal(t, "foo", metadata["name"])
	require.Equal(t, "bar", metadata["description"])
	require.Equal(t, "TODO: Fill the gadget homepage URL", metadata["homepageURL"])
	require.Equal(t, map[any]any{
		"ebpf": map[any]any{
			"emitstats": true,
		},
	}, metadata["operator"])
	require.Equal(t, map[any]any{
		"operator.sort.sort": "-runtime",
	}, metadata["paramDefaults"])
}
