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

package uidgidresolver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/cachedmap"
)

// setupTestFiles creates temporary passwd and group files for testing
func setupTestFiles(t *testing.T, passwdContent, groupContent string) {
	t.Helper()

	tmpDir := t.TempDir()
	passwdPath := filepath.Join(tmpDir, "passwd")
	groupPath := filepath.Join(tmpDir, "group")

	if passwdContent != "" {
		err := os.WriteFile(passwdPath, []byte(passwdContent), 0o644)
		require.NoError(t, err)
	}
	if groupContent != "" {
		err := os.WriteFile(groupPath, []byte(groupContent), 0o644)
		require.NoError(t, err)
	}

	origPasswdPath := fullPasswdPath
	origGroupPath := fullGroupPath
	fullPasswdPath = passwdPath
	fullGroupPath = groupPath

	t.Cleanup(func() {
		fullPasswdPath = origPasswdPath
		fullGroupPath = origGroupPath
	})
}

func TestStartStopLifecycle(t *testing.T) {
	setupTestFiles(t,
		"root:x:0:0:root:/root:/bin/bash\n",
		"root:x:0:\n",
	)

	cache := &userGroupCache{}
	t.Cleanup(func() {
		cache.Stop()
		cache.Close()
	})

	// Initial state
	require.Equal(t, 0, cache.useCount)

	// First Start
	err := cache.Start()
	require.NoError(t, err)
	require.Equal(t, 1, cache.useCount)
	require.NotNil(t, cache.watcher)

	// Second Start increments count
	err = cache.Start()
	require.NoError(t, err)
	require.Equal(t, 2, cache.useCount)

	// First Stop decrements count but keeps resources
	cache.Stop()
	require.Equal(t, 1, cache.useCount)
	require.NotNil(t, cache.watcher)

	// Second Stop cleans up resources
	cache.Stop()
	require.Equal(t, 0, cache.useCount)
	assert.Nil(t, cache.watcher)
}

func TestFilesAvailable(t *testing.T) {
	tests := []struct {
		name          string
		passwdContent string
		groupContent  string
		wantErr       string
	}{
		{
			name:          "passwd missing",
			passwdContent: "", // not created
			groupContent:  "root:x:0:\n",
			wantErr:       "passwd",
		},
		{
			name:          "group missing",
			passwdContent: "root:x:0:0:root:/root:/bin/bash\n",
			groupContent:  "", // not created
			wantErr:       "group",
		},
		{
			name:          "both files exist",
			passwdContent: "root:x:0:0:root:/root:/bin/bash\n",
			groupContent:  "root:x:0:\n",
			wantErr:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupTestFiles(t, tt.passwdContent, tt.groupContent)

			err := FilesAvailable()

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrNoUserGroupFiles))
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestUpdateEntriesParsing(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected map[uint32]string
	}{
		{
			name:    "standard passwd format",
			content: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
			expected: map[uint32]string{
				0: "root",
				1: "daemon",
			},
		},
		{
			name:    "with comments and empty lines",
			content: "# comment\nroot:x:0:0:root:/root:/bin/bash\n\n# another\ntestuser:x:1000:1000:Test:/home/test:/bin/bash\n",
			expected: map[uint32]string{
				0:    "root",
				1000: "testuser",
			},
		},
		{
			name:    "with leading whitespace",
			content: "  root:x:0:0:root:/root:/bin/bash\n\tdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
			expected: map[uint32]string{
				0: "root",
				1: "daemon",
			},
		},
		{
			name:    "skips invalid lines",
			content: "root:x:0:0:root:/root:/bin/bash\ninvalid_no_colons\nshort:x\nvalid:x:1000:1000:Valid:/home/valid:/bin/bash\n",
			expected: map[uint32]string{
				0:    "root",
				1000: "valid",
			},
		},
		{
			name:     "empty file",
			content:  "",
			expected: map[uint32]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "passwd_test")
			require.NoError(t, err)
			t.Cleanup(func() { os.Remove(tmpFile.Name()) })

			_, err = tmpFile.WriteString(tt.content)
			require.NoError(t, err)
			_, err = tmpFile.Seek(0, 0)
			require.NoError(t, err)

			cache := cachedmap.NewCachedMap[uint32, string](time.Second)
			updateEntries(tmpFile, cache)

			for uid, expectedName := range tt.expected {
				name, ok := cache.Get(uid)
				assert.True(t, ok, "expected uid %d to exist", uid)
				assert.Equal(t, expectedName, name)
			}
			assert.Equal(t, len(tt.expected), len(cache.Keys()))
		})
	}
}

func TestIntegrationParsePasswdAndGroup(t *testing.T) {
	passwdContent := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"testuser:x:1000:1000:Test User:/home/testuser:/bin/bash",
	}, "\n")

	groupContent := strings.Join([]string{
		"root:x:0:",
		"daemon:x:1:",
		"testgroup:x:1000:testuser",
	}, "\n")

	setupTestFiles(t, passwdContent, groupContent)

	cache := &userGroupCache{}
	err := cache.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		cache.Stop()
		cache.Close()
	})

	// Verify users
	assert.Equal(t, "root", cache.GetUsername(0))
	assert.Equal(t, "daemon", cache.GetUsername(1))
	assert.Equal(t, "testuser", cache.GetUsername(1000))
	assert.Equal(t, "", cache.GetUsername(9999))

	// Verify groups
	assert.Equal(t, "root", cache.GetGroupname(0))
	assert.Equal(t, "daemon", cache.GetGroupname(1))
	assert.Equal(t, "testgroup", cache.GetGroupname(1000))
	assert.Equal(t, "", cache.GetGroupname(9999))
}
