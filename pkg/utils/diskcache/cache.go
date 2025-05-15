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
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	lastCleanupFile = "last_cleanup" // Dummy file to track last cleanup time
)

type CacheOpts struct {
	// BasePath is the base path where the cache will be stored.
	BasePath string
	// CleanUpInterval is how often to clean up the cache.
	CleanUpInterval time.Duration
	// CacheEntryTTL is how long to keep unused cache entries.
	CacheEntryTTL time.Duration
}

type Cache struct {
	opts        CacheOpts
	lastCleanup time.Time
}

// NewCache creates a new Cache object. It takes a CacheOpts struct as a parameter.
func NewCache(opts CacheOpts) (*Cache, error) {
	if err := os.MkdirAll(opts.BasePath, os.ModePerm); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	cache := &Cache{
		opts: opts,
	}

	if err := cache.loadLastCleanup(); err != nil {
		return nil, fmt.Errorf("loading last cleanup timestamp: %w", err)
	}

	return cache, nil
}

type CacheEntry struct {
	digest     string
	path       string
	cachedPath string
	hit        bool
}

func (c *Cache) NewEntry(path string, seed hash.Hash) (*CacheEntry, error) {
	hasher := seed
	if hasher == nil {
		hasher = sha256.New()
	}

	if err := calculateFileHash(path, hasher); err != nil {
		return nil, fmt.Errorf("calculating digest: %w", err)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))

	cachedPath := filepath.Join(c.opts.BasePath, digest)

	return &CacheEntry{
		path:       path,
		digest:     digest,
		cachedPath: cachedPath,
		hit:        fileExists(cachedPath),
	}, nil
}

func (c *Cache) loadLastCleanup() error {
	filePath := filepath.Join(c.opts.BasePath, lastCleanupFile)
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		if _, err := os.Create(filePath); err != nil {
			return fmt.Errorf("creating last cleanup file: %w", err)
		}
		info, _ = os.Stat(filePath)
	} else if err != nil {
		return fmt.Errorf("checking last cleanup file: %w", err)
	}

	c.lastCleanup = info.ModTime()
	return nil
}

func (c *Cache) saveLastCleanup() error {
	filePath := filepath.Join(c.opts.BasePath, lastCleanupFile)
	return os.Chtimes(filePath, time.Now(), time.Now())
}

func (c *Cache) Close() error {
	if time.Since(c.lastCleanup) < c.opts.CleanUpInterval {
		return nil
	}

	err := filepath.Walk(c.opts.BasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Name() == lastCleanupFile {
			return nil
		}

		if time.Since(info.ModTime()) > c.opts.CacheEntryTTL {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("removing old cache entry: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	c.lastCleanup = time.Now()
	if err := c.saveLastCleanup(); err != nil {
		return fmt.Errorf("saving last cleanup timestamp: %w", err)
	}

	return nil
}

func (c *CacheEntry) Get() (bool, string) {
	if c.hit {
		// Update last used time
		os.Chtimes(c.cachedPath, time.Now(), time.Now())
		return true, c.cachedPath
	}
	return false, ""
}

func (c *CacheEntry) Put(path string) error {
	// if the cache was a hit we don't need to do anything
	if c.hit {
		return nil
	}
	err := copyFile(path, c.cachedPath)
	if err != nil {
		return fmt.Errorf("copying file: %w", err)
	}
	c.hit = true
	return nil
}

func calculateFileHash(filePath string, hasher hash.Hash) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("calculating hash: %w", err)
	}

	return nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("creating destination file: %w", err)
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("copying file content: %w", err)
	}

	if err = destFile.Sync(); err != nil {
		return fmt.Errorf("syncing destination file: %w", err)
	}

	return nil
}
