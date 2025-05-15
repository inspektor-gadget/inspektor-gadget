// Copyright 2025 The Inspektor Gadget authors
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

// Package diskcache provides a simple disk-based cache for files. The
// NewCache() returns a Cache object that represents a cache on the disk. It can
// be used to create CacheEntry objects that represent files in the cache.

package diskcache

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func assertFilesEqual(t *testing.T, file1, file2 string) {
	content1, err := os.ReadFile(file1)
	require.NoError(t, err, "Failed to read file: %s", file1)

	content2, err := os.ReadFile(file2)
	require.NoError(t, err, "Failed to read file: %s", file2)

	require.Equal(t, content1, content2, "File contents are not equal: %s and %s", file1, file2)
}

func TestCache(t *testing.T) {
	tests := []struct {
		name    string
		opts    CacheOpts
		operate func(t *testing.T, cache *Cache, testFile string)
	}{
		{
			name: "Cache Miss",
			opts: CacheOpts{
				CleanUpInterval: 10 * time.Second,
				CacheEntryTTL:   10 * time.Second,
			},
			operate: func(t *testing.T, cache *Cache, testFile string) {
				entry, err := cache.NewEntry(testFile, nil)
				require.NoError(t, err)
				hit, _ := entry.Get()
				require.False(t, hit, "Expected cache miss for nonexistent file")
			},
		},
		{
			name: "Cache Hit Same Entry",
			opts: CacheOpts{
				CleanUpInterval: 10 * time.Second,
				CacheEntryTTL:   10 * time.Second,
			},
			operate: func(t *testing.T, cache *Cache, testFile string) {
				entry, err := cache.NewEntry(testFile, nil)
				require.NoError(t, err)
				err = entry.Put(testFile)
				require.NoError(t, err)

				hit, cachedPath := entry.Get()
				require.True(t, hit, "Expected cache hit for existing file")
				// check if files in cachedPath is the same as testFile
				assertFilesEqual(t, testFile, cachedPath)
			},
		},
		{
			name: "Cache Hit Different Entries",
			opts: CacheOpts{
				CleanUpInterval: 10 * time.Second,
				CacheEntryTTL:   10 * time.Second,
			},
			operate: func(t *testing.T, cache *Cache, testFile string) {
				entry1, err := cache.NewEntry(testFile, nil)
				require.NoError(t, err)
				err = entry1.Put(testFile)
				require.NoError(t, err)

				entry2, err := cache.NewEntry(testFile, nil)
				require.NoError(t, err)
				hit, cachedPath := entry2.Get()
				require.True(t, hit, "Expected cache hit for existing file")

				// check if files in cachedPath is the same as testFile
				assertFilesEqual(t, testFile, cachedPath)
			},
		},
		{
			name: "Cache Cleanup",
			opts: CacheOpts{
				CleanUpInterval: 1 * time.Second,
				CacheEntryTTL:   2 * time.Second,
			},
			operate: func(t *testing.T, cache *Cache, testFile string) {
				entry, err := cache.NewEntry(testFile, nil)
				require.NoError(t, err)
				err = entry.Put(testFile)
				require.NoError(t, err)

				hit, cachedPath := entry.Get()
				require.True(t, hit, "Expected cache hit before cleanup")
				require.FileExists(t, cachedPath, "Cached file should exist before cleanup")

				time.Sleep(3 * time.Second) // Wait for TTL to expire

				err = cache.Close()
				require.NoError(t, err)
				require.NoFileExists(t, cachedPath, "Cached file should be removed after cleanup")
			},
		},
		{
			name: "Cache With Seed Hasher",
			opts: CacheOpts{
				CleanUpInterval: 10 * time.Second,
				CacheEntryTTL:   10 * time.Second,
			},
			operate: func(t *testing.T, cache *Cache, testFile string) {
				entry1, err := cache.NewEntry(testFile, nil)
				require.NoError(t, err)
				err = entry1.Put(testFile)
				require.NoError(t, err)
				hit, _ := entry1.Get()
				require.True(t, hit, "Expected cache hit")

				// entry with different seed hasher should be a miss
				hasher := sha256.New()
				hasher.Write([]byte("seed"))

				entry2, err := cache.NewEntry(testFile, hasher)
				require.NoError(t, err)

				hit, _ = entry2.Get()
				require.False(t, hit, "Expected cache miss with seed hasher")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			testFile := filepath.Join(tempDir, "testfile")
			err := os.WriteFile(testFile, []byte("test content"), 0o600)
			require.NoError(t, err)

			tt.opts.BasePath = tempDir

			cache, err := NewCache(tt.opts)

			require.NoError(t, err)
			defer cache.Close()

			tt.operate(t, cache, testFile)
		})
	}
}
